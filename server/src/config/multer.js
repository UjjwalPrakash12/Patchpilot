const multer = require('multer');
const path = require('path');
const fs = require('fs');
const os = require('os');
const config = require('./index');

const uploadDir = path.join(config.TEMP_DIR, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const ext = path.extname(file.originalname);
    cb(null, `upload-${uniqueSuffix}${ext}`);
  },
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (ext !== '.zip') {
    return cb(new Error('Only .zip archive files are allowed'), false);
  }
  cb(null, true);
};

const upload = multer({
  storage,
  limits: {
    fileSize: config.UPLOAD_MAX_SIZE,
  },
  fileFilter,
});

module.exports = upload;
