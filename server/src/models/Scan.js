const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const scannerResultSchema = new mongoose.Schema(
  {
    status: {
      type: String,
      enum: ['pending', 'running', 'completed', 'failed', 'skipped'],
      default: 'pending',
    },
    findingCount: {
      type: Number,
      default: 0,
    },
    error: {
      type: String,
      default: null,
    },
  },
  { _id: false }
);

const scanSchema = new mongoose.Schema(
  {
    scanId: {
      type: String,
      default: uuidv4,
      unique: true,
      index: true,
      required: true,
    },
    projectName: {
      type: String,
      required: true,
      trim: true,
    },
    submissionType: {
      type: String,
      enum: ['zip', 'github'],
      required: true,
    },
    repositoryUrl: {
      type: String,
      trim: true,
      default: null,
    },
    status: {
      type: String,
      enum: ['queued', 'preparing', 'scanning', 'analyzing', 'completed', 'failed'],
      default: 'queued',
      index: true,
    },
    scannerResults: {
      secrets: {
        type: scannerResultSchema,
        default: () => ({ status: 'pending', findingCount: 0, error: null }),
      },
      dependencies: {
        type: scannerResultSchema,
        default: () => ({ status: 'pending', findingCount: 0, error: null }),
      },
      staticAnalysis: {
        type: scannerResultSchema,
        default: () => ({ status: 'pending', findingCount: 0, error: null }),
      },
      configuration: {
        type: scannerResultSchema,
        default: () => ({ status: 'pending', findingCount: 0, error: null }),
      },
      projectSpecific: {
        type: scannerResultSchema,
        default: () => ({ status: 'pending', findingCount: 0, error: null }),
      },
    },
    totalFindings: {
      type: Number,
      default: 0,
    },
    criticalCount: {
      type: Number,
      default: 0,
    },
    highCount: {
      type: Number,
      default: 0,
    },
    mediumCount: {
      type: Number,
      default: 0,
    },
    lowCount: {
      type: Number,
      default: 0,
    },
    infoCount: {
      type: Number,
      default: 0,
    },
    errorMessage: {
      type: String,
      default: null,
    },
    startedAt: {
      type: Date,
      default: null,
    },
    completedAt: {
      type: Date,
      default: null,
    },
    ownerToken: {
      type: String,
      index: true,
      default: uuidv4,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform: (doc, ret) => {
        delete ret._id;
        delete ret.__v;
        delete ret.ownerToken;
        return ret;
      },
    },
  }
);

module.exports = mongoose.model('Scan', scanSchema);
