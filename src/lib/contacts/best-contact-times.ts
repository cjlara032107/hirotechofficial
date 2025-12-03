/**
 * ML-like algorithm to compute multiple "best times to contact"
 * a person based on message timestamps and reply behavior.
 * 
 * Converted from JavaScript to TypeScript for Next.js integration.
 * All times are formatted in Philippine Time (PHT, UTC+8).
 */

import { formatTimePHT, getDayNamePHT } from '@/lib/utils/timezone';

export interface Interaction {
  sentTime: Date;
  replyTime: Date | null;
}

export interface BestTimeWindow {
  start: Date;
  end: Date;
  score: number;
  prob: number;
  activityRate: number;
}

/**
 * Convert Date -> [hourSin, hourCos] in [0, 24)
 * to represent hour of day as cyclic features
 */
function hourToCyclic(date: Date): [number, number] {
  const hour = date.getHours() + date.getMinutes() / 60;
  const angle = (2 * Math.PI * hour) / 24;
  return [Math.sin(angle), Math.cos(angle)];
}

/**
 * Convert Date -> [dowSin, dowCos] in [0, 7)
 * 0 = Monday, 6 = Sunday (remapped from JS getDay())
 */
function dowToCyclic(date: Date): [number, number] {
  // JS: 0 = Sunday, 6 = Saturday
  const jsDow = date.getDay();
  const dow = (jsDow + 6) % 7; // make 0 = Monday
  const angle = (2 * Math.PI * dow) / 7;
  return [Math.sin(angle), Math.cos(angle)];
}

/**
 * Is this date on weekend? (Sat or Sun)
 */
function isWeekend(date: Date): number {
  const jsDow = date.getDay(); // 0=Sun,6=Sat
  return jsDow === 0 || jsDow === 6 ? 1 : 0;
}

/**
 * Get hour-of-week index [0..167]
 * 0 = Monday 00:00-01:00, ..., 167 = Sunday 23:00-24:00
 */
function hourOfWeekIndex(date: Date): number {
  const jsDow = date.getDay(); // 0=Sun..6=Sat
  const dow = (jsDow + 6) % 7; // 0=Mon..6=Sun
  return dow * 24 + date.getHours();
}

/**
 * Build a 168-bin histogram of contact's activity, normalized to [0,1].
 * contactMessages: Date[] of times THEY sent messages.
 */
function buildActivityHistogram(contactMessages: Date[]): number[] {
  if (contactMessages.length === 0) {
    // Return uniform distribution if no messages
    return new Array(168).fill(1 / 168);
  }

  const bins = new Array(168).fill(0);
  for (const dt of contactMessages) {
    if (!(dt instanceof Date) || isNaN(dt.getTime())) {
      console.warn('[buildActivityHistogram] Invalid date encountered, skipping');
      continue;
    }
    const idx = hourOfWeekIndex(dt);
    if (idx >= 0 && idx < 168) {
      bins[idx] += 1;
    }
  }
  // Laplace smoothing + normalization
  const smoothed = bins.map((c) => c + 1);
  const maxVal = Math.max(...smoothed);
  if (maxVal === 0) {
    // Fallback to uniform if all zeros
    return new Array(168).fill(1 / 168);
  }
  return smoothed.map((v) => v / maxVal);
}

/**
 * Simple logistic regression for binary classification.
 * Implemented from scratch with gradient descent.
 */
class LogisticRegression {
  private weights: number[];
  private bias: number;

  constructor(
    private numFeatures: number,
    private learningRate: number = 0.1,
    private l2: number = 0.001,
    private epochs: number = 500
  ) {
    this.weights = new Array(numFeatures).fill(0);
    this.bias = 0;
  }

  private sigmoid(z: number): number {
    if (z > 20) return 1;
    if (z < -20) return 0;
    return 1 / (1 + Math.exp(-z));
  }

  /**
   * Train the model
   */
  fit(X: number[][], y: number[]): void {
    const nSamples = X.length;
    if (nSamples === 0) return;

    for (let epoch = 0; epoch < this.epochs; epoch++) {
      const dW = new Array(this.numFeatures).fill(0);
      let dB = 0;

      for (let i = 0; i < nSamples; i++) {
        const xi = X[i];
        const yi = y[i];

        let z = this.bias;
        for (let j = 0; j < this.numFeatures; j++) {
          z += this.weights[j] * xi[j];
        }

        const p = this.sigmoid(z);
        const error = p - yi;

        for (let j = 0; j < this.numFeatures; j++) {
          dW[j] += error * xi[j];
        }
        dB += error;
      }

      for (let j = 0; j < this.numFeatures; j++) {
        dW[j] /= nSamples;
      }
      dB /= nSamples;

      // L2 regularization
      for (let j = 0; j < this.numFeatures; j++) {
        dW[j] += this.l2 * this.weights[j];
      }

      // Gradient step
      for (let j = 0; j < this.numFeatures; j++) {
        this.weights[j] -= this.learningRate * dW[j];
      }
      this.bias -= this.learningRate * dB;
    }
  }

  /**
   * Predict P(y=1 | x)
   */
  predictProba(x: number[]): number {
    let z = this.bias;
    for (let j = 0; j < this.numFeatures; j++) {
      z += this.weights[j] * x[j];
    }
    return this.sigmoid(z);
  }
}

/**
 * Build training data from interactions.
 */
function buildTrainingSet(
  interactions: Interaction[],
  activityHistogram: number[],
  replyWindowHours: number = 1
): { X: number[][]; y: number[] } {
  const X: number[][] = [];
  const y: number[] = [];

  for (const inter of interactions) {
    const sent = inter.sentTime;
    const reply = inter.replyTime;

    let label = 0;
    if (reply instanceof Date) {
      const diffHours = (reply.getTime() - sent.getTime()) / (1000 * 60 * 60);
      if (diffHours >= 0 && diffHours <= replyWindowHours) {
        label = 1;
      }
    }

    const [hourSin, hourCos] = hourToCyclic(sent);
    const [dowSin, dowCos] = dowToCyclic(sent);
    const weekend = isWeekend(sent);
    const hourWeekIdx = hourOfWeekIndex(sent);
    const activityRate = activityHistogram[hourWeekIdx];

    // Feature vector – extend here if you have more signals
    const features = [hourSin, hourCos, dowSin, dowCos, weekend, activityRate];

    X.push(features);
    y.push(label);
  }

  return { X, y };
}

/**
 * Train a model for a single contact.
 */
function trainContactModel(
  interactions: Interaction[],
  contactMessages: Date[],
  replyWindowHours: number = 1
): { model: LogisticRegression; activityHistogram: number[] } {
  if (interactions.length === 0) {
    throw new Error('No interactions available for training');
  }

  const activityHistogram = buildActivityHistogram(contactMessages);
  const { X, y } = buildTrainingSet(interactions, activityHistogram, replyWindowHours);

  if (X.length === 0 || y.length === 0) {
    throw new Error(`No training data available for this contact (${interactions.length} interactions, ${contactMessages.length} contact messages)`);
  }

  if (X[0] === undefined) {
    throw new Error('Training data is empty or malformed');
  }

  const numFeatures = X[0].length;
  if (numFeatures === 0) {
    throw new Error('Feature vector is empty');
  }

  const model = new LogisticRegression(numFeatures, 0.2, 0.001, 800);
  model.fit(X, y);

  return { model, activityHistogram };
}

/**
 * Generate candidate time slots over a reference week.
 */
function generateCandidateSlots(stepMinutes: number = 30): Date[] {
  const candidates: Date[] = [];
  // Reference Monday (date itself doesn't matter, only weekday structure)
  // 2025-01-06 is a Monday
  const baseMonday = new Date(2025, 0, 6, 0, 0, 0, 0);
  const totalMinutes = 7 * 24 * 60;

  for (let m = 0; m < totalMinutes; m += stepMinutes) {
    const dt = new Date(baseMonday.getTime() + m * 60 * 1000);
    candidates.push(dt);
  }

  return candidates;
}

interface ScoredCandidate {
  date: Date;
  prob: number;
  activityRate: number;
  score: number;
}

/**
 * Score candidate slots:
 * finalScore = alpha * predictedProb + (1 - alpha) * activityRate
 */
function scoreCandidates(
  candidates: Date[],
  model: LogisticRegression,
  activityHistogram: number[],
  alpha: number = 0.7
): ScoredCandidate[] {
  const scored: ScoredCandidate[] = [];

  for (const dt of candidates) {
    const [hourSin, hourCos] = hourToCyclic(dt);
    const [dowSin, dowCos] = dowToCyclic(dt);
    const weekend = isWeekend(dt);
    const hourWeekIdx = hourOfWeekIndex(dt);
    const activityRate = activityHistogram[hourWeekIdx];

    const features = [hourSin, hourCos, dowSin, dowCos, weekend, activityRate];

    const prob = model.predictProba(features);
    const finalScore = alpha * prob + (1 - alpha) * activityRate;

    scored.push({
      date: dt,
      prob,
      activityRate,
      score: finalScore,
    });
  }

  return scored;
}

/**
 * Pick top K non-overlapping windows by score.
 */
function pickBestTimeWindows(
  scored: ScoredCandidate[],
  topK: number = 5,
  windowMinutes: number = 60
): BestTimeWindow[] {
  const sorted = scored.slice().sort((a, b) => b.score - a.score);
  const windows: BestTimeWindow[] = [];

  for (const item of sorted) {
    if (windows.length >= topK) break;

    const start = item.date;
    const end = new Date(start.getTime() + windowMinutes * 60 * 1000);

    // check overlap with already chosen windows
    let overlaps = false;
    for (const w of windows) {
      const latestStart = new Date(Math.max(w.start.getTime(), start.getTime()));
      const earliestEnd = new Date(Math.min(w.end.getTime(), end.getTime()));

      if (latestStart < earliestEnd) {
        overlaps = true;
        break;
      }
    }

    if (!overlaps) {
      windows.push({
        start,
        end,
        score: item.score,
        prob: item.prob,
        activityRate: item.activityRate,
      });
    }
  }

  return windows;
}

export interface ComputeBestContactTimesParams {
  interactions: Interaction[];
  contactMessages: Date[];
  replyWindowHours?: number;
  candidateStepMinutes?: number;
  alpha?: number;
  topK?: number;
  windowMinutes?: number;
}

/**
 * Main function: compute best contact times for one person.
 */
export function computeBestContactTimes(
  params: ComputeBestContactTimesParams
): BestTimeWindow[] {
  const {
    interactions,
    contactMessages,
    replyWindowHours = 1,
    candidateStepMinutes = 30,
    alpha = 0.7,
    topK = 5,
    windowMinutes = 60,
  } = params;

  const { model, activityHistogram } = trainContactModel(
    interactions,
    contactMessages,
    replyWindowHours
  );

  const candidates = generateCandidateSlots(candidateStepMinutes);
  const scored = scoreCandidates(candidates, model, activityHistogram, alpha);
  const windows = pickBestTimeWindows(scored, topK, windowMinutes);

  return windows;
}

/**
 * Format best time windows for storage in database (JSON format)
 * All times are formatted in Philippine Time (PHT, UTC+8)
 */
export function formatBestContactTimesForStorage(
  windows: BestTimeWindow[],
  totalMessagesAnalyzed: number,
  averageReplyTime?: number,
  fastestReplyTime?: number,
  slowestReplyTime?: number
): Record<string, unknown> {
  if (!Array.isArray(windows) || windows.length === 0) {
    throw new Error('No best time windows provided');
  }

  const dayNames = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  
  const bestContactTimes = windows.map((window, index) => {
    if (!(window.start instanceof Date) || isNaN(window.start.getTime())) {
      throw new Error(`Invalid start date in window ${index}: ${window.start}`);
    }
    if (!(window.end instanceof Date) || isNaN(window.end.getTime())) {
      throw new Error(`Invalid end date in window ${index}: ${window.end}`);
    }

    // Use PHT timezone for day and time formatting
    const dayOfWeek = getDayNamePHT(window.start);
    const startTime = formatTimePHT(window.start);
    const endTime = formatTimePHT(window.end);
    
    return {
      dayOfWeek,
      timeRange: `${startTime} - ${endTime}`,
      confidence: Math.round(window.score * 100),
      averageReplyTime: averageReplyTime, // Include at window level for display
      messageCount: undefined, // Not available at window level, but page handles it gracefully
    };
  });

  return {
    bestContactTimes,
    totalMessagesAnalyzed,
    averageReplyTime,
    fastestReplyTime,
    slowestReplyTime,
    computedAt: new Date().toISOString(),
    timezone: 'Asia/Manila', // Explicitly mark as PHT
  };
}

