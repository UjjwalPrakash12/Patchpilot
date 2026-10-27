const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const findingSchema = new mongoose.Schema(
  {
    findingId: {
      type: String,
      default: uuidv4,
      unique: true,
      index: true,
      required: true,
    },
    scanId: {
      type: String,
      required: true,
      index: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    category: {
      type: String,
      enum: ['secrets', 'dependencies', 'source-code', 'configuration'],
      required: true,
      index: true,
    },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'info'],
      required: true,
      index: true,
    },
    confidence: {
      type: String,
      enum: ['high', 'medium', 'low'],
      default: 'medium',
    },
    status: {
      type: String,
      enum: ['open', 'fix-proposed', 'fixed-verified', 'accepted-risk', 'false-positive'],
      default: 'open',
      index: true,
    },
    scanner: {
      type: String,
      required: true,
    },
    ruleId: {
      type: String,
      required: true,
      index: true,
    },
    filePath: {
      type: String,
      required: true,
    },
    startLine: {
      type: Number,
      default: 1,
    },
    endLine: {
      type: Number,
      default: 1,
    },
    evidence: {
      type: String,
      default: '',
    },
    description: {
      type: String,
      default: '',
    },
    impact: {
      type: String,
      default: '',
    },
    remediation: {
      type: String,
      default: '',
    },
    codeSnippet: {
      type: String,
      default: '',
    },
    fixedCode: {
      type: String,
      default: null,
    },
    references: {
      type: [String],
      default: [],
    },
    verificationStatus: {
      type: String,
      enum: ['not-checked', 'passed', 'failed', 'inconclusive'],
      default: 'not-checked',
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform: (doc, ret) => {
        delete ret._id;
        delete ret.__v;
        return ret;
      },
    },
  }
);

// Compound index for querying findings by scan and severity or category
findingSchema.index({ scanId: 1, severity: 1 });
findingSchema.index({ scanId: 1, category: 1 });
findingSchema.index({ scanId: 1, status: 1 });

module.exports = mongoose.model('Finding', findingSchema);
