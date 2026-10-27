const fs = require('fs');
const path = require('path');
const https = require('https');
const { URL } = require('url');
const { extractZip } = require('./archiveService');

/**
 * Validates GitHub URL and extracts owner and repo
 * @param {string} repoUrl
 * @returns {{ owner: string, repo: string }}
 */
function parseAndValidateGitHubUrl(repoUrl) {
  if (!repoUrl || typeof repoUrl !== 'string') {
    throw new Error('A valid GitHub repository URL is required');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(repoUrl.trim());
  } catch {
    throw new Error('Invalid URL format');
  }

  // SSRF Protection: Protocol must be https, hostname strictly github.com
  if (parsedUrl.protocol !== 'https:') {
    throw new Error('Only secure HTTPS protocol is permitted');
  }

  if (parsedUrl.hostname.toLowerCase() !== 'github.com') {
    throw new Error('Repository URL must be on github.com');
  }

  if (parsedUrl.port && parsedUrl.port !== '443') {
    throw new Error('Custom ports are not allowed');
  }

  if (parsedUrl.username || parsedUrl.password) {
    throw new Error('Embedded credentials in repository URL are forbidden');
  }

  // Path format: /owner/repo or /owner/repo.git
  const pathParts = parsedUrl.pathname.split('/').filter(Boolean);
  if (pathParts.length < 2) {
    throw new Error('Invalid GitHub repository path: expected /owner/repo');
  }

  const owner = pathParts[0];
  let repo = pathParts[1];
  if (repo.endsWith('.git')) {
    repo = repo.slice(0, -4);
  }

  const safeNameRegex = /^[a-zA-Z0-9_.-]+$/;
  if (!safeNameRegex.test(owner) || !safeNameRegex.test(repo)) {
    throw new Error('Invalid repository owner or name characters');
  }

  return { owner, repo };
}

/**
 * Checks if a hostname resolves or targets private IP space
 * @param {string} hostname
 */
function isDisallowedHost(hostname) {
  const lower = hostname.toLowerCase();
  if (
    lower === 'localhost' ||
    lower === '127.0.0.1' ||
    lower === '0.0.0.0' ||
    lower === '::1' ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal')
  ) {
    return true;
  }
  // Allow only github.com and codeload.github.com
  return !(lower === 'github.com' || lower.endsWith('.github.com'));
}

/**
 * Safe HTTP GET download that follows redirects with SSRF protection
 * @param {string} initialUrl
 * @param {string} destinationFile
 * @param {number} maxRedirects
 * @returns {Promise<void>}
 */
function safeDownload(initialUrl, destinationFile, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    let currentUrl = initialUrl;
    let redirectsCount = 0;

    function requestUrl(targetUrl) {
      if (redirectsCount > maxRedirects) {
        return reject(new Error('Too many HTTP redirects during repository download'));
      }

      let parsed;
      try {
        parsed = new URL(targetUrl);
      } catch (err) {
        return reject(new Error(`Invalid redirect URL: ${err.message}`));
      }

      if (parsed.protocol !== 'https:') {
        return reject(new Error('Redirects must remain on secure HTTPS protocol'));
      }

      if (isDisallowedHost(parsed.hostname)) {
        return reject(new Error(`Disallowed redirect host (SSRF Protection): ${parsed.hostname}`));
      }

      const options = {
        headers: {
          'User-Agent': 'PatchPilot-Security-Scanner/1.0',
          Accept: 'application/vnd.github.v3+json, application/zip',
        },
      };

      const req = https.get(targetUrl, options, (res) => {
        // Handle 3xx Redirects
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          redirectsCount++;
          const nextUrl = new URL(res.headers.location, targetUrl).toString();
          res.resume(); // Discard data
          return requestUrl(nextUrl);
        }

        if (res.statusCode !== 200) {
          res.resume();
          return reject(
            new Error(`Failed to download repository: HTTP ${res.statusCode} ${res.statusMessage}`)
          );
        }

        let downloadedBytes = 0;
        let isAborted = false;
        const fileStream = fs.createWriteStream(destinationFile);

        res.on('data', (chunk) => {
          downloadedBytes += chunk.length;
          if (downloadedBytes > config.UPLOAD_MAX_SIZE && !isAborted) {
            isAborted = true;
            req.destroy();
            fileStream.destroy();
            try {
              if (fs.existsSync(destinationFile)) fs.unlinkSync(destinationFile);
            } catch {}
            reject(
              new Error(
                `Repository archive exceeds maximum allowed size of ${(config.UPLOAD_MAX_SIZE / (1024 * 1024)).toFixed(0)}MB`
              )
            );
          }
        });

        res.pipe(fileStream);

        fileStream.on('finish', () => {
          if (!isAborted) {
            fileStream.close(() => resolve());
          }
        });

        fileStream.on('error', (err) => {
          try {
            if (fs.existsSync(destinationFile)) fs.unlinkSync(destinationFile);
          } catch {}
          reject(err);
        });
      });

      req.on('error', (err) => {
        fs.unlink(destinationFile, () => {});
        reject(err);
      });

      req.setTimeout(30000, () => {
        req.destroy();
        reject(new Error('Repository download timed out after 30 seconds'));
      });
    }

    requestUrl(currentUrl);
  });
}

/**
 * Downloads a public GitHub repository zipball and extracts it
 * @param {string} repoUrl
 * @param {string} destPath
 * @returns {Promise<string>} - Path to the root project directory
 */
async function cloneRepository(repoUrl, destPath) {
  const { owner, repo } = parseAndValidateGitHubUrl(repoUrl);

  if (!fs.existsSync(destPath)) {
    fs.mkdirSync(destPath, { recursive: true });
  }

  const zipPath = path.join(destPath, `${owner}_${repo}.zip`);
  const extractPath = path.join(destPath, 'repo-content');
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/zipball`;

  try {
    await safeDownload(apiUrl, zipPath);
    await extractZip(zipPath, extractPath);

    // Clean up zip file
    try {
      if (fs.existsSync(zipPath)) {
        fs.unlinkSync(zipPath);
      }
    } catch {
      // Ignore cleanup error
    }

    // GitHub zipball wraps contents inside a single root dir (e.g. owner-repo-sha)
    const entries = fs.readdirSync(extractPath, { withFileTypes: true });
    const subdirs = entries.filter((e) => e.isDirectory());
    if (subdirs.length === 1 && entries.length === 1) {
      return path.join(extractPath, subdirs[0].name);
    }

    return extractPath;
  } catch (err) {
    // Clean up on failure
    try {
      if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath);
    } catch {}
    throw err;
  }
}

module.exports = {
  cloneRepository,
  parseAndValidateGitHubUrl,
};
