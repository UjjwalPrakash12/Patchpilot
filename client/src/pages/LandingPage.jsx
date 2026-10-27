import { Link } from 'react-router-dom';
import {
  Upload,
  Search,
  FileText,
  Wrench,
  Key,
  Package,
  Code,
  Settings,
  Shield,
  ArrowRight,
  AlertTriangle,
  CheckCircle,
  FileCode,
  Eye,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { getCategoryBadgeClasses } from '../utils/severity';

export default function LandingPage() {
  const steps = [
    {
      step: '01',
      title: 'Submit Code',
      description: 'Upload a ZIP archive of your project or paste a public GitHub repository link.',
      icon: Upload,
    },
    {
      step: '02',
      title: 'Automated Scan',
      description: 'Our automated multi-scanner pipeline inspects code, secrets, dependencies, and configuration.',
      icon: Search,
    },
    {
      step: '03',
      title: 'Review Findings',
      description: 'Get plain-English explanations of security weaknesses, severity levels, and real-world impact.',
      icon: FileText,
    },
    {
      step: '04',
      title: 'Fix Issues',
      description: 'Review copy-paste remediations and download patches to secure your application in minutes.',
      icon: Wrench,
    },
  ];

  const checkCategories = [
    {
      title: 'Secret Detection',
      icon: Key,
      iconColor: 'text-purple-400',
      borderColor: 'border-purple-500/20',
      bullets: [
        'API keys, JWT secrets, OAuth tokens, and database credentials',
        'High-entropy strings and hardcoded service passwords',
        'Accidental credential exposure in source and config files',
      ],
    },
    {
      title: 'Dependency Vulnerabilities',
      icon: Package,
      iconColor: 'text-cyan-400',
      borderColor: 'border-cyan-500/20',
      bullets: [
        'Known CVE vulnerabilities across npm and package dependencies',
        'Direct and transitive dependencies with known exploits',
        'Actionable upgrade recommendations and patch versions',
      ],
    },
    {
      title: 'Code Security',
      icon: Code,
      iconColor: 'text-emerald-400',
      borderColor: 'border-emerald-500/20',
      bullets: [
        'Dangerous eval(), prototype pollution, and unsafe regex execution',
        'Cross-Site Scripting (XSS) risks and improper innerHTML usage',
        'Unsanitized inputs feeding SQL, NoSQL, and shell commands',
      ],
    },
    {
      title: 'Configuration Issues',
      icon: Settings,
      iconColor: 'text-amber-400',
      borderColor: 'border-amber-500/20',
      bullets: [
        'Overly permissive CORS rules allowing arbitrary origins (*)',
        'Missing security response headers like Helmet CSP and HSTS',
        'Missing API rate limiting and insecure session cookie flags',
      ],
    },
  ];

  const limitations = [
    'Does not replace a dedicated human penetration test or professional third-party audit.',
    'Cannot detect bespoke multi-step business logic vulnerabilities specific to domain workflows.',
    'Performs static code & configuration analysis only; does not execute dynamic attacks against live servers.',
    'AI-generated remediation patches should always be reviewed and tested in staging before deploying to production.',
  ];

  return (
    <div className="space-y-24 py-12 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      {/* Hero Section */}
      <section className="text-center max-w-4xl mx-auto pt-6 pb-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold mb-6">
          <Shield className="h-3.5 w-3.5" />
          <span>Automated Security Scanner for Modern Web Apps</span>
        </div>
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-gray-100 leading-tight">
          Find Security Weaknesses in Your AI-Built Website
        </h1>
        <p className="mt-6 text-lg sm:text-xl text-gray-400 leading-relaxed max-w-2xl mx-auto">
          Scans your code for exposed secrets, vulnerable packages, insecure patterns, and dangerous configurations—with plain English explanations and ready-to-apply fixes.
        </p>
        <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            to="/scan/new"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-lg text-base font-semibold text-gray-950 bg-emerald-400 hover:bg-emerald-300 transition-colors shadow-lg shadow-emerald-950/50"
          >
            <span>Scan Your Project Now</span>
            <ArrowRight className="h-4 w-4" />
          </Link>
          <Link
            to="/history"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-lg text-base font-medium text-gray-300 bg-gray-900 hover:bg-gray-800 border border-gray-800 hover:border-gray-700 transition-colors"
          >
            <span>View Recent Scans</span>
          </Link>
        </div>
        <div className="mt-6 flex items-center justify-center gap-6 text-xs text-gray-500">
          <span className="flex items-center gap-1.5">
            <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
            No account required
          </span>
          <span className="flex items-center gap-1.5">
            <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
            Fast analysis in seconds
          </span>
          <span className="flex items-center gap-1.5">
            <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
            Remediation patches
          </span>
        </div>
      </section>

      {/* How it Works Section */}
      <section>
        <div className="text-center max-w-2xl mx-auto mb-12">
          <h2 className="text-2xl sm:text-3xl font-bold text-gray-100">
            How It Works
          </h2>
          <p className="mt-2 text-sm sm:text-base text-gray-400">
            A frictionless workflow designed to surface critical flaws quickly.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {steps.map(({ step, title, description, icon: Icon }) => (
            <div
              key={step}
              className="bg-gray-900 border border-gray-800 rounded-xl p-6 relative flex flex-col justify-between hover:border-gray-700 transition-colors"
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2.5 rounded-lg bg-gray-800 text-emerald-400">
                    <Icon className="h-5 w-5" />
                  </div>
                  <span className="text-xs font-mono font-bold text-gray-600">
                    {step}
                  </span>
                </div>
                <h3 className="text-lg font-semibold text-gray-200 mb-2">
                  {title}
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* What We Check Section */}
      <section>
        <div className="text-center max-w-2xl mx-auto mb-12">
          <h2 className="text-2xl sm:text-3xl font-bold text-gray-100">
            What We Check
          </h2>
          <p className="mt-2 text-sm sm:text-base text-gray-400">
            Four specialized detection engines guarding your application layers.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {checkCategories.map(({ title, icon: Icon, iconColor, borderColor, bullets }) => (
            <div
              key={title}
              className={`bg-gray-900 border ${borderColor} rounded-xl p-6 hover:border-gray-700 transition-colors`}
            >
              <div className="flex items-center gap-3 mb-4">
                <div className={`p-2.5 rounded-lg bg-gray-950 border border-gray-800 ${iconColor}`}>
                  <Icon className="h-5 w-5" />
                </div>
                <h3 className="text-lg font-semibold text-gray-200">{title}</h3>
              </div>
              <ul className="space-y-2.5">
                {bullets.map((bullet, idx) => (
                  <li key={idx} className="flex items-start gap-2.5 text-sm text-gray-400">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 mt-2 flex-shrink-0" />
                    <span>{bullet}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* Sample Finding Preview */}
      <section className="bg-gray-900 border border-gray-800 rounded-2xl p-6 sm:p-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-6 border-b border-gray-800">
          <div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 mb-2">
              <Eye className="h-3.5 w-3.5" />
              <span>SAMPLE FINDING PREVIEW</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-gray-100">
              Clear, Actionable Findings
            </h2>
            <p className="text-sm text-gray-400 mt-1">
              Every finding explains what happened, why it matters, and gives you tested remediation steps.
            </p>
          </div>
          <Link
            to="/scan/new"
            className="inline-flex items-center gap-1 text-sm font-medium text-emerald-400 hover:text-emerald-300 self-start sm:self-auto"
          >
            <span>Scan your code</span>
            <ArrowRight className="h-4 w-4" />
          </Link>
        </div>

        {/* Realistic Sample Finding Card */}
        <div className="bg-gray-950 border border-gray-800 rounded-xl p-5 sm:p-6 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <SeverityBadge severity="high" />
              <span className={getCategoryBadgeClasses('secrets')}>
                secrets
              </span>
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-800 text-gray-400 border border-gray-700">
                Rule: SEC-HARDCODED-API-KEY
              </span>
            </div>
            <span className="text-xs text-gray-500 font-mono">Scanner: Gitleaks Engine</span>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-gray-100">
              Hardcoded API Key Detected
            </h3>
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mt-1">
              <FileCode className="h-3.5 w-3.5 text-gray-500" />
              <span className="font-mono text-gray-300">config/api.js</span>
              <span className="text-gray-500">:15</span>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-lg p-3.5 font-mono text-xs overflow-x-auto text-gray-300">
            <div className="text-gray-600">// config/api.js: line 15</div>
            <div className="text-red-400 mt-1 font-semibold">
              - const STRIPE_SECRET = 'MOCK_STRIPE_SECRET_KEY_FOR_DEMO_ONLY';
            </div>
            <div className="text-emerald-400 mt-1 font-semibold">
              + const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
            </div>
          </div>

          <div className="text-sm text-gray-400 leading-relaxed">
            <strong className="text-gray-300">Why it matters:</strong> Production payment keys or third-party API credentials committed to version control can be harvested by automated attackers, leading to account takeover or financial liability.
          </div>

          <div className="pt-2 flex items-center justify-between border-t border-gray-900 flex-wrap gap-2">
            <span className="text-xs text-gray-500">
              Confidence: <span className="text-gray-300 font-medium">High</span> • Status: <span className="text-emerald-400 font-medium">Open</span>
            </span>
            <span className="text-xs text-emerald-400 font-medium">
              Automated Fix Proposal Ready →
            </span>
          </div>
        </div>
      </section>

      {/* Limitations Section */}
      <section className="bg-gray-900/50 border border-gray-800 rounded-xl p-6 sm:p-8">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-6 w-6 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <h2 className="text-lg font-semibold text-gray-100">
              Important Limitations & Disclaimer
            </h2>
            <p className="text-sm text-gray-400 mt-1 mb-4">
              PatchPilot is designed as an automated first-line scanning tool to catch common pitfalls. We believe in being transparent about boundaries:
            </p>
            <ul className="space-y-2">
              {limitations.map((item, idx) => (
                <li key={idx} className="flex items-start gap-2 text-sm text-gray-400">
                  <span className="text-gray-600 font-bold">•</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}
