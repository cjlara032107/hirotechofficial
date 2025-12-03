# Monitoring and Observability Guide

This guide covers the comprehensive monitoring system implemented for the Hiro platform, including error rates, performance metrics, user feedback, resource usage, and production issue tracking.

## Table of Contents

1. [Error Rate Monitoring](#error-rate-monitoring)
2. [Performance Metrics](#performance-metrics)
3. [User Feedback Monitoring](#user-feedback-monitoring)
4. [Resource Usage Monitoring](#resource-usage-monitoring)
5. [Production Issue Documentation](#production-issue-documentation)
6. [API Endpoints](#api-endpoints)
7. [Best Practices](#best-practices)

---

## Error Rate Monitoring

### Overview

The error rate monitoring system tracks all errors across the application, providing insights into error trends, types, and patterns over time.

### Features

- **Time-based Aggregations**: View error rates for 1 hour, 24 hours, 7 days, or 30 days
- **Error Grouping**: Group errors by type, code, or time window
- **Trend Analysis**: Compare error rates between time periods
- **Recent Errors**: View the most recent errors with full context

### API Endpoint

**GET** `/api/monitoring/error-rates`

#### Query Parameters

- `timeWindow` (optional): `'1h'` | `'24h'` | `'7d'` | `'30d'` (default: `'24h'`)
- `groupBy` (optional): `'hour'` | `'day'` (default: `'hour'` for <7d, `'day'` for >=7d)
- `errorType` (optional): Filter by specific error type
- `errorCode` (optional): Filter by specific error code
- `level` (optional): `'error'` | `'warn'` | `'info'` (default: `'error'`)

#### Example Request

```bash
GET /api/monitoring/error-rates?timeWindow=24h&groupBy=hour
```

#### Example Response

```json
{
  "success": true,
  "data": {
    "timeWindow": "24h",
    "groupBy": "hour",
    "totalErrors": 42,
    "errorRate": 1.75,
    "trend": -15.5,
    "errorsByType": [
      { "errorType": "Prisma.P1001", "count": 20 },
      { "errorType": "HTTP.500", "count": 15 },
      { "errorType": "Axios.ECONNREFUSED", "count": 7 }
    ],
    "errorsByCode": [
      { "errorCode": "P1001", "count": 20 },
      { "errorCode": "500", "count": 15 }
    ],
    "timeSeries": [
      { "time": "2025-01-15T10:00:00", "count": 5 },
      { "time": "2025-01-15T11:00:00", "count": 3 }
    ],
    "recentErrors": [...]
  }
}
```

---

## Performance Metrics

### Overview

Performance metrics track database query performance, memory usage, CPU usage, and network I/O to identify bottlenecks and optimize system performance.

### Features

- **Database Query Performance**: Track query duration, slow queries, error rates
- **Memory Usage**: Monitor heap usage, RSS, and memory trends
- **CPU Usage**: Track CPU utilization (user and system time)
- **Network I/O**: Monitor bytes sent/received and request counts

### API Endpoint

**GET** `/api/monitoring/metrics`

#### Example Response

```json
{
  "success": true,
  "data": {
    "database": {
      "totalQueries": 1234,
      "averageDuration": 45.2,
      "p50Duration": 30,
      "p95Duration": 120,
      "p99Duration": 250,
      "slowQueries": 12,
      "errorCount": 5,
      "errorRate": 0.4,
      "queriesByModel": {
        "User": 500,
        "Contact": 734
      }
    },
    "memory": {
      "current": { "heapUsedMB": 150.5, "rssMB": 200.3 },
      "average": { "heapUsedMB": 145.2 },
      "peak": { "heapUsedMB": 180.0 }
    },
    "errors": {
      "totalErrors": 50,
      "errorsByType": { "Prisma.P1001": 10 },
      "errorRate": 2.1
    },
    "resources": {
      "cpu": {
        "current": { "user": 15.5, "system": 5.2, "total": 20.7 },
        "average": { "total": 18.3 }
      },
      "network": {
        "total": {
          "bytesReceived": 1024000,
          "bytesSent": 512000,
          "requests": 1000
        }
      }
    }
  }
}
```

---

## User Feedback Monitoring

### Overview

User feedback monitoring aggregates and analyzes feedback from users stored in the Contact model, providing insights into user satisfaction and sentiment.

### Features

- **Sentiment Analysis**: Automatically categorize feedback as positive, negative, or neutral
- **Time-based Trends**: Track feedback over time (24h, 7d, 30d)
- **Feedback Rate**: Calculate feedback per day
- **Recent Feedback**: View the most recent feedback entries

### API Endpoint

**GET** `/api/monitoring/user-feedback`

#### Query Parameters

- `timeWindow` (optional): `'24h'` | `'7d'` | `'30d'` (default: `'30d'`)
- `organizationId` (optional): Filter by organization

#### Example Response

```json
{
  "success": true,
  "data": {
    "timeWindow": "30d",
    "totalFeedback": 150,
    "feedbackRate": 5.0,
    "sentiment": {
      "positive": 100,
      "negative": 20,
      "neutral": 30,
      "positivePercent": 67,
      "negativePercent": 13,
      "neutralPercent": 20
    },
    "feedbackByDay": [
      { "date": "2025-01-15", "count": 5 },
      { "date": "2025-01-16", "count": 3 }
    ],
    "recentFeedback": [...]
  }
}
```

---

## Resource Usage Monitoring

### Overview

Resource usage monitoring tracks CPU, memory, network, and disk usage to ensure the system operates within acceptable resource limits.

### API Endpoint

**GET** `/api/monitoring/resource-usage`

#### Example Response

```json
{
  "success": true,
  "data": {
    "cpu": {
      "current": {
        "user": 15.5,
        "system": 5.2,
        "total": 20.7
      },
      "average": {
        "user": 12.3,
        "system": 4.1,
        "total": 16.4
      },
      "peak": {
        "total": 45.0,
        "timestamp": 1705320000000
      }
    },
    "memory": {
      "current": {
        "heapUsedMB": 150.5,
        "rssMB": 200.3
      },
      "average": {
        "heapUsedMB": 145.2
      }
    },
    "network": {
      "current": {
        "bytesReceived": 1024000,
        "bytesSent": 512000,
        "requests": 1000
      },
      "last24Hours": {
        "bytesReceivedPerHour": 42666,
        "bytesSentPerHour": 21333,
        "requestsPerHour": 41
      }
    },
    "disk": {
      "note": "Disk usage monitoring requires system-level access"
    }
  }
}
```

---

## Production Issue Documentation

### Overview

The production issue documentation system allows teams to track, document, and resolve production incidents systematically.

### Features

- **Issue Creation**: Document new production issues with severity, type, and description
- **Status Management**: Track issues as ACTIVE, RESOLVED, or ACKNOWLEDGED
- **Root Cause Analysis**: Document root causes and resolutions
- **Metadata**: Store additional context (affected services, related errors, etc.)

### API Endpoints

#### Create Issue

**POST** `/api/monitoring/production-issues`

```json
{
  "title": "Database Connection Pool Exhaustion",
  "description": "Database connection pool reached maximum connections",
  "severity": "ERROR",
  "type": "DATABASE_POOL_EXHAUSTION",
  "affectedServices": ["api", "worker"],
  "rootCause": "Long-running queries not releasing connections",
  "resolution": "Increased pool size and added connection timeout"
}
```

#### List Issues

**GET** `/api/monitoring/production-issues`

Query Parameters:
- `status`: `'ACTIVE'` | `'RESOLVED'` | `'ACKNOWLEDGED'`
- `severity`: `'INFO'` | `'WARNING'` | `'ERROR'` | `'CRITICAL'`
- `type`: AlertType enum value
- `limit`: number (default: 50)
- `offset`: number (default: 0)

#### Get Issue

**GET** `/api/monitoring/production-issues/[id]`

#### Update Issue

**PATCH** `/api/monitoring/production-issues/[id]`

```json
{
  "status": "RESOLVED",
  "resolution": "Fixed by increasing connection pool size",
  "rootCause": "Connection pool too small for peak load"
}
```

---

## API Endpoints Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/monitoring/error-rates` | GET | Get error rate metrics |
| `/api/monitoring/metrics` | GET | Get all system metrics |
| `/api/monitoring/user-feedback` | GET | Get user feedback metrics |
| `/api/monitoring/resource-usage` | GET | Get resource usage metrics |
| `/api/monitoring/production-issues` | GET | List production issues |
| `/api/monitoring/production-issues` | POST | Create production issue |
| `/api/monitoring/production-issues/[id]` | GET | Get specific issue |
| `/api/monitoring/production-issues/[id]` | PATCH | Update issue |

---

## Best Practices

### Error Monitoring

1. **Set Up Alerts**: Configure alerts for high error rates (>5% error rate)
2. **Regular Review**: Review error trends weekly to identify patterns
3. **Root Cause Analysis**: Document root causes for recurring errors
4. **Error Categorization**: Use consistent error types and codes

### Performance Monitoring

1. **Baseline Metrics**: Establish baseline performance metrics
2. **Slow Query Alerts**: Set alerts for queries >1000ms
3. **Memory Leaks**: Monitor for increasing memory usage over time
4. **Capacity Planning**: Use metrics to plan for scale

### User Feedback

1. **Regular Analysis**: Review feedback weekly
2. **Sentiment Trends**: Track sentiment trends over time
3. **Action Items**: Create action items for negative feedback
4. **Follow-up**: Follow up on critical feedback

### Production Issues

1. **Document Everything**: Document all production issues, even minor ones
2. **Root Cause Analysis**: Always document root cause and resolution
3. **Post-Mortems**: Conduct post-mortems for critical issues
4. **Learnings**: Update documentation based on learnings

### Resource Usage

1. **Set Thresholds**: Define acceptable resource usage thresholds
2. **Monitor Trends**: Watch for gradual increases in resource usage
3. **Capacity Planning**: Use metrics for capacity planning
4. **Optimization**: Optimize based on resource usage patterns

---

## Integration with External Tools

### Recommended Integrations

- **Sentry**: For error tracking and alerting
- **Datadog/New Relic**: For comprehensive APM
- **Grafana**: For visualization and dashboards
- **PagerDuty**: For incident management

### Exporting Data

All monitoring endpoints return JSON data that can be easily integrated with external monitoring tools via webhooks or scheduled exports.

---

## Troubleshooting

### Common Issues

1. **High Error Rates**: Check database connections, API rate limits, and external service health
2. **Memory Leaks**: Review long-running processes and check for memory leaks in code
3. **Slow Queries**: Optimize database queries, add indexes, or increase connection pool
4. **High CPU Usage**: Profile code to identify CPU-intensive operations

### Getting Help

For issues with the monitoring system itself, check:
- System logs: `console.log` and `console.error` output
- Database: Check `ErrorLog` and `JobLog` tables
- API responses: Review error responses from monitoring endpoints

---

## Future Enhancements

- Real-time dashboards
- Automated alerting
- Machine learning for anomaly detection
- Integration with external monitoring services
- Custom metrics and KPIs
- Performance regression detection









