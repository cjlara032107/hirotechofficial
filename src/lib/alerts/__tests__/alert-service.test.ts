/**
 * Tests for Alert Service
 * 
 * Tests cover:
 * - Alert creation with cooldown prevention
 * - Alert resolution
 * - Alert acknowledgment
 * - Duplicate alert prevention
 * - Integration with monitoring
 */

// Mock @prisma/client first, before any imports
jest.mock('@prisma/client', () => ({
  AlertType: {
    JOB_FAILURE: 'JOB_FAILURE',
    HIGH_ERROR_RATE: 'HIGH_ERROR_RATE',
    PERFORMANCE_DEGRADATION: 'PERFORMANCE_DEGRADATION',
    API_RATE_LIMIT_EXHAUSTION: 'API_RATE_LIMIT_EXHAUSTION',
    DATABASE_CONNECTION_ISSUE: 'DATABASE_CONNECTION_ISSUE',
    DATABASE_POOL_EXHAUSTION: 'DATABASE_POOL_EXHAUSTION',
  },
  AlertSeverity: {
    WARNING: 'WARNING',
    ERROR: 'ERROR',
    CRITICAL: 'CRITICAL',
  },
  AlertStatus: {
    ACTIVE: 'ACTIVE',
    RESOLVED: 'RESOLVED',
    ACKNOWLEDGED: 'ACKNOWLEDGED',
  },
}));

import { AlertService, CreateAlertInput } from '../alert-service';
import { prisma } from '@/lib/db';
import { AlertType, AlertSeverity, AlertStatus } from '@prisma/client';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    systemAlert: {
      findFirst: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      findMany: jest.fn(),
    },
  },
}));

jest.mock('@/lib/utils/logger', () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
    log: jest.fn(),
  },
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('AlertService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    // Reset static state
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (AlertService as any).lastAlertTimes.clear();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('createAlert', () => {
    const alertInput: CreateAlertInput = {
      type: AlertType.JOB_FAILURE,
      severity: AlertSeverity.ERROR,
      title: 'Test Alert',
      message: 'This is a test alert',
      metadata: { test: true },
    };

    it('should create a new alert', async () => {
      (mockedPrisma.systemAlert.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.systemAlert.create as jest.Mock).mockResolvedValue({
        id: 'alert-1',
        ...alertInput,
        status: AlertStatus.ACTIVE,
        createdAt: new Date(),
      });

      await AlertService.createAlert(alertInput);

      expect(mockedPrisma.systemAlert.create).toHaveBeenCalledWith({
        data: {
          type: alertInput.type,
          severity: alertInput.severity,
          title: alertInput.title,
          message: alertInput.message,
          metadata: alertInput.metadata,
          status: AlertStatus.ACTIVE,
        },
      });
    });

    it('should not create duplicate alert within cooldown period', async () => {
      (mockedPrisma.systemAlert.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.systemAlert.create as jest.Mock).mockResolvedValue({
        id: 'alert-1',
        ...alertInput,
        status: AlertStatus.ACTIVE,
        createdAt: new Date(),
      });

      // Create first alert
      await AlertService.createAlert(alertInput);
      expect(mockedPrisma.systemAlert.create).toHaveBeenCalledTimes(1);

      // Try to create same alert immediately (within cooldown)
      await AlertService.createAlert(alertInput);
      expect(mockedPrisma.systemAlert.create).toHaveBeenCalledTimes(1); // Still 1
    });

    it('should create alert after cooldown period expires', async () => {
      (mockedPrisma.systemAlert.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.systemAlert.create as jest.Mock).mockResolvedValue({
        id: 'alert-1',
        ...alertInput,
        status: AlertStatus.ACTIVE,
        createdAt: new Date(),
      });

      // Create first alert
      await AlertService.createAlert(alertInput);
      expect(mockedPrisma.systemAlert.create).toHaveBeenCalledTimes(1);

      // Advance time past cooldown (5 minutes)
      jest.advanceTimersByTime(6 * 60 * 1000);

      // Try to create same alert again
      await AlertService.createAlert(alertInput);
      expect(mockedPrisma.systemAlert.create).toHaveBeenCalledTimes(2);
    });

    it('should not create duplicate alert if active alert exists within last hour', async () => {
      const existingAlert = {
        id: 'alert-1',
        type: AlertType.JOB_FAILURE,
        status: AlertStatus.ACTIVE,
        createdAt: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
      };

      (mockedPrisma.systemAlert.findFirst as jest.Mock).mockResolvedValue(existingAlert);

      await AlertService.createAlert(alertInput);

      expect(mockedPrisma.systemAlert.create).not.toHaveBeenCalled();
    });

    it('should create alert if existing alert is older than one hour', async () => {
      const oldAlert = {
        id: 'alert-1',
        type: AlertType.JOB_FAILURE,
        status: AlertStatus.ACTIVE,
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
      };

      (mockedPrisma.systemAlert.findFirst as jest.Mock).mockResolvedValue(oldAlert);
      (mockedPrisma.systemAlert.create as jest.Mock).mockResolvedValue({
        id: 'alert-2',
        ...alertInput,
        status: AlertStatus.ACTIVE,
        createdAt: new Date(),
      });

      await AlertService.createAlert(alertInput);

      expect(mockedPrisma.systemAlert.create).toHaveBeenCalled();
    });

    it('should handle database errors gracefully', async () => {
      (mockedPrisma.systemAlert.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.systemAlert.create as jest.Mock).mockRejectedValue(
        new Error('Database error')
      );

      await expect(AlertService.createAlert(alertInput)).resolves.not.toThrow();
    });

    it('should use default severity if not provided', async () => {
      const inputWithoutSeverity: CreateAlertInput = {
        type: AlertType.JOB_FAILURE,
        title: 'Test Alert',
        message: 'Test message',
      };

      (mockedPrisma.systemAlert.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.systemAlert.create as jest.Mock).mockResolvedValue({
        id: 'alert-1',
        ...inputWithoutSeverity,
        severity: AlertSeverity.WARNING,
        status: AlertStatus.ACTIVE,
        createdAt: new Date(),
      });

      await AlertService.createAlert(inputWithoutSeverity);

      expect(mockedPrisma.systemAlert.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          severity: AlertSeverity.WARNING, // Default
        }),
      });
    });
  });

  describe('resolveAlert', () => {
    it('should resolve an alert', async () => {
      const alertId = 'alert-1';
      (mockedPrisma.systemAlert.update as jest.Mock).mockResolvedValue({
        id: alertId,
        status: AlertStatus.RESOLVED,
        resolvedAt: new Date(),
      });

      await AlertService.resolveAlert(alertId);

      expect(mockedPrisma.systemAlert.update).toHaveBeenCalledWith({
        where: { id: alertId },
        data: {
          status: AlertStatus.RESOLVED,
          resolvedAt: expect.any(Date),
        },
      });
    });

    it('should handle database errors gracefully', async () => {
      const alertId = 'alert-1';
      (mockedPrisma.systemAlert.update as jest.Mock).mockRejectedValue(
        new Error('Database error')
      );

      await expect(AlertService.resolveAlert(alertId)).resolves.not.toThrow();
    });
  });

  describe('resolveAlertsByType', () => {
    it('should resolve all active alerts of a specific type', async () => {
      const alertType = AlertType.JOB_FAILURE;
      (mockedPrisma.systemAlert.updateMany as jest.Mock).mockResolvedValue({
        count: 3,
      });

      await AlertService.resolveAlertsByType(alertType);

      expect(mockedPrisma.systemAlert.updateMany).toHaveBeenCalledWith({
        where: {
          type: alertType,
          status: AlertStatus.ACTIVE,
        },
        data: {
          status: AlertStatus.RESOLVED,
          resolvedAt: expect.any(Date),
        },
      });
    });

    it('should handle database errors gracefully', async () => {
      const alertType = AlertType.JOB_FAILURE;
      (mockedPrisma.systemAlert.updateMany as jest.Mock).mockRejectedValue(
        new Error('Database error')
      );

      await expect(AlertService.resolveAlertsByType(alertType)).resolves.not.toThrow();
    });
  });

  describe('getActiveAlerts', () => {
    it('should return active alerts', async () => {
      const mockAlerts = [
        {
          id: 'alert-1',
          type: AlertType.JOB_FAILURE,
          status: AlertStatus.ACTIVE,
          createdAt: new Date(),
        },
        {
          id: 'alert-2',
          type: AlertType.HIGH_ERROR_RATE,
          status: AlertStatus.ACTIVE,
          createdAt: new Date(),
        },
      ];

      (mockedPrisma.systemAlert.findMany as jest.Mock).mockResolvedValue(mockAlerts);

      const result = await AlertService.getActiveAlerts();

      expect(result).toEqual(mockAlerts);
      expect(mockedPrisma.systemAlert.findMany).toHaveBeenCalledWith({
        where: {
          status: AlertStatus.ACTIVE,
        },
        orderBy: {
          createdAt: 'desc',
        },
        take: 50, // Default limit
      });
    });

    it('should respect limit parameter', async () => {
      (mockedPrisma.systemAlert.findMany as jest.Mock).mockResolvedValue([]);

      await AlertService.getActiveAlerts(10);

      expect(mockedPrisma.systemAlert.findMany).toHaveBeenCalledWith({
        where: {
          status: AlertStatus.ACTIVE,
        },
        orderBy: {
          createdAt: 'desc',
        },
        take: 10,
      });
    });

    it('should return empty array on database error', async () => {
      (mockedPrisma.systemAlert.findMany as jest.Mock).mockRejectedValue(
        new Error('Database error')
      );

      const result = await AlertService.getActiveAlerts();

      expect(result).toEqual([]);
    });
  });

  describe('acknowledgeAlert', () => {
    it('should acknowledge an alert', async () => {
      const alertId = 'alert-1';
      const userId = 'user-123';
      (mockedPrisma.systemAlert.update as jest.Mock).mockResolvedValue({
        id: alertId,
        status: AlertStatus.ACKNOWLEDGED,
        acknowledgedAt: new Date(),
        acknowledgedBy: userId,
      });

      await AlertService.acknowledgeAlert(alertId, userId);

      expect(mockedPrisma.systemAlert.update).toHaveBeenCalledWith({
        where: { id: alertId },
        data: {
          status: AlertStatus.ACKNOWLEDGED,
          acknowledgedAt: expect.any(Date),
          acknowledgedBy: userId,
        },
      });
    });

    it('should handle database errors gracefully', async () => {
      const alertId = 'alert-1';
      const userId = 'user-123';
      (mockedPrisma.systemAlert.update as jest.Mock).mockRejectedValue(
        new Error('Database error')
      );

      await expect(AlertService.acknowledgeAlert(alertId, userId)).resolves.not.toThrow();
    });
  });
});

