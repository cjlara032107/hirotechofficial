/**
 * Tests for Alert Monitor
 * 
 * Tests cover:
 * - Job failure detection and alerting
 * - Error rate monitoring and alerting
 * - Performance degradation detection and alerting
 * - Auto-resolution of alerts
 * - Integration with alert service
 */

// Mock @prisma/client first, before any imports
jest.mock('@prisma/client', () => ({
  AlertType: {
    JOB_FAILURE: 'JOB_FAILURE',
    HIGH_ERROR_RATE: 'HIGH_ERROR_RATE',
    PERFORMANCE_DEGRADATION: 'PERFORMANCE_DEGRADATION',
  },
  AlertStatus: {
    ACTIVE: 'ACTIVE',
    RESOLVED: 'RESOLVED',
    ACKNOWLEDGED: 'ACKNOWLEDGED',
  },
}));

import {
  checkJobFailures,
  checkErrorRates,
  checkPerformanceDegradation,
  runMonitoringChecks,
  autoResolveAlerts,
  MonitoringConfig,
} from '../alert-monitor';
import * as alertService from '@/lib/alerts/alert-service';
import { prisma } from '@/lib/db';
import { AlertType, AlertStatus } from '@prisma/client';

// Mock dependencies
jest.mock('@/lib/alerts/alert-service', () => ({
  alertJobFailure: jest.fn(),
  alertHighErrorRate: jest.fn(),
  alertPerformanceDegradation: jest.fn(),
}));

jest.mock('@/lib/db', () => ({
  prisma: {
    jobLog: {
      findMany: jest.fn(),
      count: jest.fn(),
    },
    errorLog: {
      findMany: jest.fn(),
      count: jest.fn(),
    },
    systemAlert: {
      findMany: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
  },
}));

jest.mock('@/lib/prisma-error-handler', () => ({
  safePrismaOperation: jest.fn((fn) => fn()),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedAlertJobFailure = alertService.alertJobFailure as jest.MockedFunction<typeof alertService.alertJobFailure>;
const mockedAlertHighErrorRate = alertService.alertHighErrorRate as jest.MockedFunction<typeof alertService.alertHighErrorRate>;
const mockedAlertPerformanceDegradation = alertService.alertPerformanceDegradation as jest.MockedFunction<typeof alertService.alertPerformanceDegradation>;

describe('Alert Monitor', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('checkJobFailures', () => {
    const defaultConfig: MonitoringConfig = {
      jobFailureThreshold: 3,
      jobFailureTimeWindowMinutes: 15,
      errorRateThreshold: 10,
      errorRateTimeWindowMinutes: 5,
      performanceDegradationPercent: 50,
      performanceBaselineWindowDays: 7,
      performanceCheckWindowMinutes: 30,
    };

    it('should not alert when no job failures exist', async () => {
      (mockedPrisma.jobLog.findMany as jest.Mock).mockResolvedValue([]);

      await checkJobFailures(defaultConfig);

      expect(mockedAlertJobFailure).not.toHaveBeenCalled();
    });

    it('should alert when job failures exceed threshold', async () => {
      const failedJobs = [
        {
          id: 'job-1',
          jobId: 'job-1',
          jobType: 'facebook_sync',
          status: 'failed',
          error: 'Connection timeout',
          createdAt: new Date(),
        },
        {
          id: 'job-2',
          jobId: 'job-2',
          jobType: 'facebook_sync',
          status: 'failed',
          error: 'API rate limit',
          createdAt: new Date(),
        },
        {
          id: 'job-3',
          jobId: 'job-3',
          jobType: 'facebook_sync',
          status: 'failed',
          error: 'Network error',
          createdAt: new Date(),
        },
      ];

      (mockedPrisma.jobLog.findMany as jest.Mock).mockResolvedValue(failedJobs);

      await checkJobFailures(defaultConfig);

      expect(mockedAlertJobFailure).toHaveBeenCalled();
    });

    it('should not alert when failures are below threshold', async () => {
      const failedJobs = [
        {
          id: 'job-1',
          jobId: 'job-1',
          jobType: 'facebook_sync',
          status: 'failed',
          error: 'Connection timeout',
          createdAt: new Date(),
        },
      ];

      (mockedPrisma.jobLog.findMany as jest.Mock).mockResolvedValue(failedJobs);

      await checkJobFailures(defaultConfig);

      expect(mockedAlertJobFailure).not.toHaveBeenCalled();
    });

    it('should group failures by job type', async () => {
      const failedJobs = [
        {
          id: 'job-1',
          jobId: 'job-1',
          jobType: 'facebook_sync',
          status: 'failed',
          error: 'Error 1',
          createdAt: new Date(),
        },
        {
          id: 'job-2',
          jobId: 'job-2',
          jobType: 'facebook_sync',
          status: 'failed',
          error: 'Error 2',
          createdAt: new Date(),
        },
        {
          id: 'job-3',
          jobId: 'job-3',
          jobType: 'ai_analysis',
          status: 'failed',
          error: 'Error 3',
          createdAt: new Date(),
        },
        {
          id: 'job-4',
          jobId: 'job-4',
          jobType: 'ai_analysis',
          status: 'failed',
          error: 'Error 4',
          createdAt: new Date(),
        },
      ];

      (mockedPrisma.jobLog.findMany as jest.Mock).mockResolvedValue(failedJobs);

      await checkJobFailures({
        ...defaultConfig,
        jobFailureThreshold: 2,
      });

      // Should alert for both job types
      expect(mockedAlertJobFailure).toHaveBeenCalledTimes(2);
    });

    it('should handle database errors gracefully', async () => {
      (mockedPrisma.jobLog.findMany as jest.Mock).mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(checkJobFailures(defaultConfig)).resolves.not.toThrow();
    });
  });

  describe('checkErrorRates', () => {
    const defaultConfig: MonitoringConfig = {
      jobFailureThreshold: 3,
      jobFailureTimeWindowMinutes: 15,
      errorRateThreshold: 10,
      errorRateTimeWindowMinutes: 5,
      performanceDegradationPercent: 50,
      performanceBaselineWindowDays: 7,
      performanceCheckWindowMinutes: 30,
    };

    it('should not alert when no errors exist', async () => {
      (mockedPrisma.errorLog.findMany as jest.Mock).mockResolvedValue([]);

      await checkErrorRates(defaultConfig);

      expect(mockedAlertHighErrorRate).not.toHaveBeenCalled();
    });

    it('should alert when error rate exceeds threshold', async () => {
      const errorLogs = Array.from({ length: 60 }, (_, i) => ({
        id: `error-${i}`,
        level: 'error',
        createdAt: new Date(),
      }));

      (mockedPrisma.errorLog.findMany as jest.Mock).mockResolvedValue(errorLogs);

      await checkErrorRates(defaultConfig);

      expect(mockedAlertHighErrorRate).toHaveBeenCalled();
    });

    it('should not alert when error rate is below threshold', async () => {
      const errorLogs = Array.from({ length: 20 }, (_, i) => ({
        id: `error-${i}`,
        level: 'error',
        createdAt: new Date(),
      }));

      (mockedPrisma.errorLog.findMany as jest.Mock).mockResolvedValue(errorLogs);

      await checkErrorRates(defaultConfig);

      expect(mockedAlertHighErrorRate).not.toHaveBeenCalled();
    });

    it('should calculate error rate correctly', async () => {
      const errorLogs = Array.from({ length: 50 }, (_, i) => ({
        id: `error-${i}`,
        level: 'error',
        createdAt: new Date(),
      }));

      (mockedPrisma.errorLog.findMany as jest.Mock).mockResolvedValue(errorLogs);

      await checkErrorRates(defaultConfig);

      expect(mockedAlertHighErrorRate).toHaveBeenCalled();
    });

    it('should handle database errors gracefully', async () => {
      (mockedPrisma.errorLog.findMany as jest.Mock).mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(checkErrorRates(defaultConfig)).resolves.not.toThrow();
    });
  });

  describe('checkPerformanceDegradation', () => {
    const defaultConfig: MonitoringConfig = {
      jobFailureThreshold: 3,
      jobFailureTimeWindowMinutes: 15,
      errorRateThreshold: 10,
      errorRateTimeWindowMinutes: 5,
      performanceDegradationPercent: 50,
      performanceBaselineWindowDays: 7,
      performanceCheckWindowMinutes: 30,
    };

    it('should not alert when no recent jobs exist', async () => {
      (mockedPrisma.jobLog.findMany as jest.Mock).mockResolvedValueOnce([]);

      await checkPerformanceDegradation(defaultConfig);

      expect(mockedAlertPerformanceDegradation).not.toHaveBeenCalled();
    });

    it('should not alert when no baseline data exists', async () => {
      const recentJobs = [
        {
          jobType: 'facebook_sync',
          duration: 5000,
          createdAt: new Date(),
        },
      ];

      (mockedPrisma.jobLog.findMany as jest.Mock)
        .mockResolvedValueOnce(recentJobs) // Recent jobs
        .mockResolvedValueOnce([]); // Baseline jobs

      await checkPerformanceDegradation(defaultConfig);

      expect(mockedAlertPerformanceDegradation).not.toHaveBeenCalled();
    });

    it('should alert when performance degrades significantly', async () => {
      const recentJobs = [
        {
          jobType: 'facebook_sync',
          duration: 5000, // 5 seconds (50% slower than baseline)
          createdAt: new Date(),
        },
        {
          jobType: 'facebook_sync',
          duration: 5500,
          createdAt: new Date(),
        },
      ];

      const baselineJobs = [
        {
          jobType: 'facebook_sync',
          duration: 2000, // 2 seconds baseline
        },
        {
          jobType: 'facebook_sync',
          duration: 2500,
        },
        {
          jobType: 'facebook_sync',
          duration: 3000,
        },
      ];

      (mockedPrisma.jobLog.findMany as jest.Mock)
        .mockResolvedValueOnce(recentJobs)
        .mockResolvedValueOnce(baselineJobs);

      await checkPerformanceDegradation(defaultConfig);

      expect(mockedAlertPerformanceDegradation).toHaveBeenCalled();
    });

    it('should not alert when performance is within acceptable range', async () => {
      const recentJobs = [
        {
          jobType: 'facebook_sync',
          duration: 2500, // Similar to baseline
          createdAt: new Date(),
        },
      ];

      const baselineJobs = [
        {
          jobType: 'facebook_sync',
          duration: 2000,
        },
        {
          jobType: 'facebook_sync',
          duration: 2500,
        },
      ];

      (mockedPrisma.jobLog.findMany as jest.Mock)
        .mockResolvedValueOnce(recentJobs)
        .mockResolvedValueOnce(baselineJobs);

      await checkPerformanceDegradation(defaultConfig);

      expect(mockedAlertPerformanceDegradation).not.toHaveBeenCalled();
    });

    it('should handle database errors gracefully', async () => {
      (mockedPrisma.jobLog.findMany as jest.Mock).mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(checkPerformanceDegradation(defaultConfig)).resolves.not.toThrow();
    });
  });

  describe('runMonitoringChecks', () => {
    it('should run all monitoring checks', async () => {
      (mockedPrisma.jobLog.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.jobLog.count as jest.Mock).mockResolvedValue(0);
      (mockedPrisma.errorLog.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.errorLog.count as jest.Mock).mockResolvedValue(0);

      const result = await runMonitoringChecks();

      expect(result).toHaveProperty('jobFailures');
      expect(result).toHaveProperty('errorRate');
      expect(result).toHaveProperty('performanceIssues');
    });

    it('should return summary statistics', async () => {
      (mockedPrisma.jobLog.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.jobLog.count as jest.Mock).mockResolvedValue(5);
      (mockedPrisma.errorLog.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.errorLog.count as jest.Mock).mockResolvedValue(20);

      const result = await runMonitoringChecks();

      expect(result.jobFailures).toBe(5);
      expect(result.errorRate).toBeGreaterThan(0);
    });

    it('should handle errors in individual checks gracefully', async () => {
      (mockedPrisma.jobLog.findMany as jest.Mock).mockRejectedValue(
        new Error('Database error')
      );
      (mockedPrisma.errorLog.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.jobLog.count as jest.Mock).mockResolvedValue(0);
      (mockedPrisma.errorLog.count as jest.Mock).mockResolvedValue(0);

      await expect(runMonitoringChecks()).resolves.not.toThrow();
    });
  });

  describe('autoResolveAlerts', () => {
    it('should resolve job failure alerts when conditions improve', async () => {
      const activeAlert = {
        id: 'alert-1',
        type: AlertType.JOB_FAILURE,
        status: AlertStatus.ACTIVE,
        metadata: {
          jobType: 'facebook_sync',
          timeWindowMinutes: 15,
        },
        createdAt: new Date(),
      };

      (mockedPrisma.systemAlert.findMany as jest.Mock).mockResolvedValue([activeAlert]);
      (mockedPrisma.jobLog.count as jest.Mock).mockResolvedValue(1); // Below threshold

      await autoResolveAlerts();

      expect(mockedPrisma.systemAlert.update).toHaveBeenCalledWith({
        where: { id: activeAlert.id },
        data: {
          status: AlertStatus.RESOLVED,
          resolvedAt: expect.any(Date),
        },
      });
    });

    it('should not resolve alerts when conditions have not improved', async () => {
      const activeAlert = {
        id: 'alert-1',
        type: AlertType.JOB_FAILURE,
        status: AlertStatus.ACTIVE,
        metadata: {
          jobType: 'facebook_sync',
          timeWindowMinutes: 15,
        },
        createdAt: new Date(),
      };

      (mockedPrisma.systemAlert.findMany as jest.Mock).mockResolvedValue([activeAlert]);
      (mockedPrisma.jobLog.count as jest.Mock).mockResolvedValue(5); // Still above threshold

      await autoResolveAlerts();

      expect(mockedPrisma.systemAlert.update).not.toHaveBeenCalled();
    });

    it('should resolve error rate alerts when conditions improve', async () => {
      const activeAlert = {
        id: 'alert-2',
        type: AlertType.HIGH_ERROR_RATE,
        status: AlertStatus.ACTIVE,
        metadata: {
          timeWindowMinutes: 5,
          threshold: 10,
        },
        createdAt: new Date(),
      };

      (mockedPrisma.systemAlert.findMany as jest.Mock)
        .mockResolvedValueOnce([]) // Job failure alerts
        .mockResolvedValueOnce([activeAlert]); // Error rate alerts
      (mockedPrisma.errorLog.count as jest.Mock).mockResolvedValue(20); // 4 errors/min, below threshold

      await autoResolveAlerts();

      expect(mockedPrisma.systemAlert.update).toHaveBeenCalledWith({
        where: { id: activeAlert.id },
        data: {
          status: AlertStatus.RESOLVED,
          resolvedAt: expect.any(Date),
        },
      });
    });

    it('should handle missing metadata gracefully', async () => {
      const activeAlert = {
        id: 'alert-1',
        type: AlertType.JOB_FAILURE,
        status: AlertStatus.ACTIVE,
        metadata: null,
        createdAt: new Date(),
      };

      (mockedPrisma.systemAlert.findMany as jest.Mock).mockResolvedValue([activeAlert]);

      await expect(autoResolveAlerts()).resolves.not.toThrow();
    });

    it('should handle database errors gracefully', async () => {
      (mockedPrisma.systemAlert.findMany as jest.Mock).mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(autoResolveAlerts()).resolves.not.toThrow();
    });
  });
});
