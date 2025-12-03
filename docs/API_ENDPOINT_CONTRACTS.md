# API Endpoint Contracts

This document provides a comprehensive reference for all API endpoints, including request/response formats, authentication requirements, error handling, and rate limiting.

## Table of Contents

1. [General API Information](#general-api-information)
2. [Authentication Endpoints](#authentication-endpoints)
3. [Contact Endpoints](#contact-endpoints)
4. [Campaign Endpoints](#campaign-endpoints)
5. [Pipeline Endpoints](#pipeline-endpoints)
6. [Facebook Integration Endpoints](#facebook-integration-endpoints)
7. [Team Endpoints](#team-endpoints)
8. [Template Endpoints](#template-endpoints)
9. [AI Assistant Endpoints](#ai-assistant-endpoints)
10. [AI Automation Endpoints](#ai-automation-endpoints)
11. [User Profile Endpoints](#user-profile-endpoints)
12. [Webhook Endpoints](#webhook-endpoints)
13. [Error Responses](#error-responses)
14. [Rate Limiting](#rate-limiting)

---

## General API Information

### Base URL

- **Development**: `http://localhost:3000`
- **Production**: `https://your-domain.com`

### Authentication

All endpoints (except public ones) require authentication via NextAuth session cookie.

**Session Requirements:**
- Valid session token in HTTP-only cookie
- User must have `organizationId` in session
- User must have `id` in session

**Authentication Header:**
- Not required (uses cookies)
- Session is validated server-side

### Content Type

- **Request**: `application/json` (for POST/PATCH/PUT)
- **Response**: `application/json`

### Common Headers

**Request Headers:**
```
Content-Type: application/json
Cookie: next-auth.session-token=...
```

**Response Headers:**
```
Content-Type: application/json
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

### Pagination

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 50, max: 100)
- `cursor`: Cursor for cursor-based pagination (optional)

**Response Format:**
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 150,
    "totalPages": 3,
    "hasMore": true
  }
}
```

### Filtering & Sorting

**Query Parameters:**
- `filter[key]`: Filter by field value
- `sort`: Sort field (e.g., `createdAt`)
- `order`: Sort order (`asc` or `desc`, default: `desc`)

---

## Authentication Endpoints

### Check Session

**GET** `/api/auth/check-session`

Check if current session is valid.

**Authentication:** Required

**Response:**
```json
{
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "name": "User Name",
    "organizationId": "org-id",
    "role": "AGENT"
  }
}
```

**Status Codes:**
- `200`: Session valid
- `401`: Unauthorized (no session or expired)

---

## Contact Endpoints

### List Contacts

**GET** `/api/contacts`

List all contacts for the authenticated user's organization.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 50, max: 100)
- `search`: Search term (searches firstName, lastName, email)
- `tags`: Comma-separated tag IDs
- `pipelineId`: Filter by pipeline ID
- `stageId`: Filter by stage ID
- `platform`: Filter by platform (`messenger` or `instagram`)
- `leadStatus`: Filter by lead status
- `minScore`: Minimum lead score
- `maxScore`: Maximum lead score
- `dateFrom`: Filter contacts created after date (ISO 8601)
- `dateTo`: Filter contacts created before date (ISO 8601)

**Response:**
```json
[
  {
    "id": "contact-id",
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "messengerPSID": "psid-123",
    "instagramSID": "ig-123",
    "profilePicUrl": "https://...",
    "leadScore": 75,
    "leadStatus": "HOT",
    "pipelineId": "pipeline-id",
    "stageId": "stage-id",
    "facebookPageId": "page-id",
    "organizationId": "org-id",
    "createdAt": "2025-01-27T10:00:00Z",
    "updatedAt": "2025-01-27T10:00:00Z",
    "tags": [
      {
        "id": "tag-id",
        "name": "VIP",
        "color": "#ff0000"
      }
    ],
    "pipeline": {
      "id": "pipeline-id",
      "name": "Sales Pipeline"
    },
    "stage": {
      "id": "stage-id",
      "name": "Qualified"
    }
  }
]
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `500`: Server error

### Get Contact

**GET** `/api/contacts/[id]`

Get a single contact by ID.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Contact ID (UUID/CUID)

**Query Parameters:**
- `includeMessages`: Include conversation messages (default: false)
- `messagesLimit`: Limit number of messages (default: 20)

**Response:**
```json
{
  "id": "contact-id",
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  "messengerPSID": "psid-123",
  "instagramSID": "ig-123",
  "profilePicUrl": "https://...",
  "leadScore": 75,
  "leadStatus": "HOT",
  "notes": "Customer notes",
  "pipelineId": "pipeline-id",
  "stageId": "stage-id",
  "facebookPageId": "page-id",
  "organizationId": "org-id",
  "createdAt": "2025-01-27T10:00:00Z",
  "updatedAt": "2025-01-27T10:00:00Z",
  "stage": {
    "id": "stage-id",
    "name": "Qualified",
    "color": "#3b82f6"
  },
  "pipeline": {
    "id": "pipeline-id",
    "name": "Sales Pipeline"
  },
  "facebookPage": {
    "id": "page-id",
    "pageName": "My Page"
  },
  "activities": [
    {
      "id": "activity-id",
      "type": "NOTE_ADDED",
      "description": "Added note",
      "user": {
        "name": "User Name",
        "email": "user@example.com"
      },
      "createdAt": "2025-01-27T10:00:00Z"
    }
  ],
  "conversations": [
    {
      "id": "conversation-id",
      "platform": "messenger",
      "messages": [
        {
          "id": "message-id",
          "content": "Hello",
          "isFromBusiness": false,
          "status": "delivered",
          "createdAt": "2025-01-27T10:00:00Z"
        }
      ]
    }
  ]
}
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `404`: Contact not found
- `500`: Server error

### Update Contact

**PATCH** `/api/contacts/[id]`

Update a contact's information.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)  
**Body Size Limit:** Medium (100 KB)

**Path Parameters:**
- `id`: Contact ID (UUID/CUID)

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "notes": "Updated notes",
  "leadScore": 80,
  "leadStatus": "HOT",
  "expectedUpdatedAt": "2025-01-27T10:00:00Z"
}
```

**Fields:**
- `firstName` (string, optional): First name
- `lastName` (string, optional): Last name
- `notes` (string, optional): Contact notes
- `leadScore` (number, optional): Lead score (0-100)
- `leadStatus` (string, optional): Lead status (`COLD`, `WARM`, `HOT`)
- `expectedUpdatedAt` (string, optional): For optimistic locking (ISO 8601)

**Response:**
```json
{
  "id": "contact-id",
  "firstName": "John",
  "lastName": "Doe",
  "notes": "Updated notes",
  "leadScore": 80,
  "leadStatus": "HOT",
  "updatedAt": "2025-01-27T10:05:00Z"
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `404`: Contact not found
- `409`: Concurrent modification (retry with fresh data)
- `500`: Server error

**Concurrent Update Handling:**
- If `expectedUpdatedAt` is provided, the endpoint checks for concurrent modifications
- Returns `409 Conflict` if contact was modified by another request
- Client should refresh and retry on 409

### Delete Contact

**DELETE** `/api/contacts/[id]`

Delete a contact.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Contact ID (UUID/CUID)

**Response:**
```json
{
  "success": true
}
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `404`: Contact not found
- `500`: Server error

### Add/Remove Tags

**POST** `/api/contacts/[id]/tags`

Add or remove tags from a contact.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Contact ID (UUID/CUID)

**Request Body:**
```json
{
  "tagIds": ["tag-id-1", "tag-id-2"],
  "action": "add" // or "remove"
}
```

**Response:**
```json
{
  "success": true,
  "contact": {
    "id": "contact-id",
    "tags": [
      {
        "id": "tag-id-1",
        "name": "VIP",
        "color": "#ff0000"
      }
    ]
  }
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `404`: Contact not found
- `500`: Server error

### Move Contact to Stage

**POST** `/api/contacts/[id]/move`

Move a contact to a different pipeline stage.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Contact ID (UUID/CUID)

**Request Body:**
```json
{
  "pipelineId": "pipeline-id",
  "stageId": "stage-id"
}
```

**Response:**
```json
{
  "success": true,
  "contact": {
    "id": "contact-id",
    "pipelineId": "pipeline-id",
    "stageId": "stage-id"
  }
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `404`: Contact or pipeline/stage not found
- `500`: Server error

### Bulk Operations

**POST** `/api/contacts/bulk`

Perform bulk operations on contacts.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)  
**Body Size Limit:** Large (1 MB)

**Request Body:**
```json
{
  "contactIds": ["id-1", "id-2", "id-3"],
  "operation": "delete", // or "update", "tag", "move"
  "data": {
    "leadStatus": "HOT",
    "tagIds": ["tag-id-1"]
  }
}
```

**Response:**
```json
{
  "success": true,
  "affected": 3,
  "errors": []
}
```

**Status Codes:**
- `200`: Success (may include errors for some items)
- `400`: Invalid request body
- `401`: Unauthorized
- `500`: Server error

### Get Contact Total Count

**GET** `/api/contacts/total-count`

Get total count of contacts (with optional filters).

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Query Parameters:**
- Same filters as list contacts endpoint

**Response:**
```json
{
  "count": 150
}
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `500`: Server error

---

## Campaign Endpoints

### List Campaigns

**GET** `/api/campaigns`

List all campaigns for the authenticated user's organization.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Query Parameters:**
- `status`: Filter by status (`DRAFT`, `SCHEDULED`, `SENDING`, `COMPLETED`, `CANCELLED`)
- `platform`: Filter by platform (`messenger` or `instagram`)

**Response:**
```json
[
  {
    "id": "campaign-id",
    "name": "Welcome Campaign",
    "description": "Welcome new contacts",
    "platform": "messenger",
    "messageTag": "ACCOUNT_UPDATE",
    "status": "SENDING",
    "rateLimit": 3600,
    "targetingType": "TAGS",
    "targetTags": ["tag-id-1"],
    "targetStageIds": [],
    "targetContactIds": [],
    "scheduledAt": null,
    "createdAt": "2025-01-27T10:00:00Z",
    "updatedAt": "2025-01-27T10:00:00Z",
    "_count": {
      "messages": 150
    },
    "template": {
      "id": "template-id",
      "name": "Welcome Template"
    },
    "facebookPage": {
      "id": "page-id",
      "pageName": "My Page"
    }
  }
]
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `500`: Server error

### Create Campaign

**POST** `/api/campaigns`

Create a new campaign.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)  
**Body Size Limit:** Medium (100 KB)

**Request Body:**
```json
{
  "name": "Welcome Campaign",
  "description": "Welcome new contacts",
  "platform": "messenger",
  "messageTag": "ACCOUNT_UPDATE",
  "facebookPageId": "page-id",
  "templateId": "template-id",
  "targetingType": "TAGS",
  "targetTags": ["tag-id-1"],
  "targetStageIds": [],
  "targetContactIds": [],
  "rateLimit": 3600,
  "scheduledAt": "2025-01-28T10:00:00Z",
  "autoFetchEnabled": true,
  "includeTags": ["tag-id-1"],
  "excludeTags": ["tag-id-2"],
  "useAiPersonalization": true,
  "aiCustomInstructions": "Make it friendly",
  "aiMessagesMap": {}
}
```

**Fields:**
- `name` (string, required): Campaign name
- `description` (string, optional): Campaign description
- `platform` (string, required): `messenger` or `instagram`
- `messageTag` (string, optional): Facebook message tag
- `facebookPageId` (string, required): Facebook page ID
- `templateId` (string, optional): Template ID
- `targetingType` (string, required): `TAGS`, `STAGES`, or `CONTACTS`
- `targetTags` (string[], optional): Tag IDs for targeting
- `targetStageIds` (string[], optional): Stage IDs for targeting
- `targetContactIds` (string[], optional): Contact IDs for targeting
- `rateLimit` (number, optional): Messages per hour (default: 3600)
- `scheduledAt` (string, optional): Schedule time (ISO 8601)
- `autoFetchEnabled` (boolean, optional): Auto-fetch contacts
- `includeTags` (string[], optional): Include tags filter
- `excludeTags` (string[], optional): Exclude tags filter
- `useAiPersonalization` (boolean, optional): Enable AI personalization
- `aiCustomInstructions` (string, optional): AI instructions
- `aiMessagesMap` (object, optional): Pre-generated AI messages

**Response:**
```json
{
  "id": "campaign-id",
  "name": "Welcome Campaign",
  "status": "DRAFT",
  "createdAt": "2025-01-27T10:00:00Z"
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `500`: Server error

### Get Campaign

**GET** `/api/campaigns/[id]`

Get a single campaign by ID.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Campaign ID (UUID/CUID)

**Response:**
```json
{
  "id": "campaign-id",
  "name": "Welcome Campaign",
  "description": "Welcome new contacts",
  "platform": "messenger",
  "messageTag": "ACCOUNT_UPDATE",
  "status": "SENDING",
  "rateLimit": 3600,
  "targetingType": "TAGS",
  "targetTags": ["tag-id-1"],
  "createdAt": "2025-01-27T10:00:00Z",
  "updatedAt": "2025-01-27T10:00:00Z",
  "template": {
    "id": "template-id",
    "name": "Welcome Template"
  },
  "facebookPage": {
    "id": "page-id",
    "pageName": "My Page"
  },
  "_count": {
    "messages": 150
  }
}
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `404`: Campaign not found
- `500`: Server error

### Update Campaign

**PATCH** `/api/campaigns/[id]`

Update a campaign.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)  
**Body Size Limit:** Medium (100 KB)

**Path Parameters:**
- `id`: Campaign ID (UUID/CUID)

**Request Body:**
```json
{
  "name": "Updated Campaign Name",
  "status": "CANCELLED"
}
```

**Response:**
```json
{
  "id": "campaign-id",
  "name": "Updated Campaign Name",
  "status": "CANCELLED",
  "updatedAt": "2025-01-27T10:05:00Z"
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `404`: Campaign not found
- `500`: Server error

### Delete Campaign

**DELETE** `/api/campaigns/[id]`

Delete a campaign.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Campaign ID (UUID/CUID)

**Response:**
```json
{
  "success": true
}
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `404`: Campaign not found
- `500`: Server error

### Start Campaign

**POST** `/api/campaigns/[id]/send`

Start sending a campaign.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Campaign ID (UUID/CUID)

**Response:**
```json
{
  "success": true,
  "campaign": {
    "id": "campaign-id",
    "status": "SENDING"
  }
}
```

**Status Codes:**
- `200`: Success
- `400`: Campaign cannot be started (wrong status)
- `401`: Unauthorized
- `404`: Campaign not found
- `500`: Server error

### Stop Campaign

**POST** `/api/campaigns/[id]/stop`

Stop a running campaign.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Campaign ID (UUID/CUID)

**Response:**
```json
{
  "success": true,
  "campaign": {
    "id": "campaign-id",
    "status": "CANCELLED"
  }
}
```

**Status Codes:**
- `200`: Success
- `400`: Campaign cannot be stopped
- `401`: Unauthorized
- `404`: Campaign not found
- `500`: Server error

### Get Failed Messages

**GET** `/api/campaigns/[id]/failed-messages`

Get failed messages for a campaign.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Campaign ID (UUID/CUID)

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 50)

**Response:**
```json
[
  {
    "id": "message-id",
    "contactId": "contact-id",
    "content": "Message content",
    "status": "FAILED",
    "error": "Rate limit exceeded",
    "createdAt": "2025-01-27T10:00:00Z"
  }
]
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `404`: Campaign not found
- `500`: Server error

---

## Pipeline Endpoints

### List Pipelines

**GET** `/api/pipelines`

List all pipelines for the authenticated user's organization.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Query Parameters:**
- `includeArchived`: Include archived pipelines (default: false)

**Response:**
```json
[
  {
    "id": "pipeline-id",
    "name": "Sales Pipeline",
    "description": "Main sales pipeline",
    "color": "#3b82f6",
    "isArchived": false,
    "createdAt": "2025-01-27T10:00:00Z",
    "updatedAt": "2025-01-27T10:00:00Z",
    "stages": [
      {
        "id": "stage-id",
        "name": "Qualified",
        "color": "#10b981",
        "type": "OPEN",
        "order": 0,
        "_count": {
          "contacts": 25
        }
      }
    ]
  }
]
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `500`: Server error

**Caching:**
- Response cached for 60 seconds
- Cache-Control: `public, s-maxage=60, stale-while-revalidate=120`

### Create Pipeline

**POST** `/api/pipelines`

Create a new pipeline with stages.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)  
**Body Size Limit:** Medium (100 KB)

**Request Body:**
```json
{
  "name": "Sales Pipeline",
  "description": "Main sales pipeline",
  "color": "#3b82f6",
  "stages": [
    {
      "name": "Qualified",
      "color": "#10b981",
      "type": "OPEN"
    },
    {
      "name": "Contacted",
      "color": "#3b82f6",
      "type": "OPEN"
    },
    {
      "name": "Won",
      "color": "#10b981",
      "type": "WON"
    }
  ]
}
```

**Fields:**
- `name` (string, required): Pipeline name
- `description` (string, optional): Pipeline description
- `color` (string, optional): Pipeline color (hex, default: `#3b82f6`)
- `stages` (array, required): Array of stage objects
  - `name` (string, required): Stage name
  - `color` (string, required): Stage color (hex)
  - `type` (string, required): Stage type (`OPEN`, `WON`, `LOST`)

**Response:**
```json
{
  "id": "pipeline-id",
  "name": "Sales Pipeline",
  "description": "Main sales pipeline",
  "color": "#3b82f6",
  "createdAt": "2025-01-27T10:00:00Z",
  "stages": [
    {
      "id": "stage-id",
      "name": "Qualified",
      "color": "#10b981",
      "type": "OPEN",
      "order": 0,
      "minScore": 0,
      "maxScore": 33
    }
  ]
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `500`: Server error

**Note:** Score ranges are automatically generated for all stages.

### Get Pipeline

**GET** `/api/pipelines/[id]`

Get a single pipeline with stages.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Pipeline ID (UUID/CUID)

**Response:**
```json
{
  "id": "pipeline-id",
  "name": "Sales Pipeline",
  "description": "Main sales pipeline",
  "color": "#3b82f6",
  "isArchived": false,
  "createdAt": "2025-01-27T10:00:00Z",
  "updatedAt": "2025-01-27T10:00:00Z",
  "stages": [
    {
      "id": "stage-id",
      "name": "Qualified",
      "color": "#10b981",
      "type": "OPEN",
      "order": 0,
      "minScore": 0,
      "maxScore": 33,
      "_count": {
        "contacts": 25
      }
    }
  ]
}
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `404`: Pipeline not found
- `500`: Server error

### Update Pipeline

**PATCH** `/api/pipelines/[id]`

Update a pipeline.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)  
**Body Size Limit:** Medium (100 KB)

**Path Parameters:**
- `id`: Pipeline ID (UUID/CUID)

**Request Body:**
```json
{
  "name": "Updated Pipeline Name",
  "isArchived": true
}
```

**Response:**
```json
{
  "id": "pipeline-id",
  "name": "Updated Pipeline Name",
  "isArchived": true,
  "updatedAt": "2025-01-27T10:05:00Z"
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `404`: Pipeline not found
- `500`: Server error

### Delete Pipeline

**DELETE** `/api/pipelines/[id]`

Delete a pipeline.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `id`: Pipeline ID (UUID/CUID)

**Response:**
```json
{
  "success": true
}
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `404`: Pipeline not found
- `500`: Server error

---

## Facebook Integration Endpoints

### List Facebook Pages

**GET** `/api/facebook/pages`

List all connected Facebook pages for the authenticated user's organization.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Response:**
```json
[
  {
    "id": "page-id",
    "pageId": "facebook-page-id",
    "pageName": "My Page",
    "instagramAccountId": "ig-account-id",
    "instagramUsername": "my_instagram",
    "autoSync": true,
    "syncInterval": 3600,
    "lastSyncedAt": "2025-01-27T10:00:00Z",
    "isActive": true,
    "createdAt": "2025-01-27T10:00:00Z"
  }
]
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `500`: Server error

### Connect Facebook Page

**POST** `/api/facebook/pages`

Connect a Facebook page to the organization.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)  
**Body Size Limit:** Medium (100 KB)

**Request Body:**
```json
{
  "pageId": "facebook-page-id",
  "pageAccessToken": "access-token",
  "autoSync": true,
  "syncInterval": 3600
}
```

**Response:**
```json
{
  "id": "page-id",
  "pageId": "facebook-page-id",
  "pageName": "My Page",
  "isActive": true,
  "createdAt": "2025-01-27T10:00:00Z"
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `500`: Server error

### Sync Contacts

**POST** `/api/facebook/sync`

Manually trigger contact synchronization from Facebook.

**Authentication:** Required  
**Rate Limit:** Strict (10/min)

**Request Body:**
```json
{
  "pageId": "page-id",
  "forceFullSync": false
}
```

**Response:**
```json
{
  "success": true,
  "jobId": "sync-job-id",
  "status": "queued"
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid request body
- `401`: Unauthorized
- `429`: Too many sync requests
- `500`: Server error

### Get Sync Status

**GET** `/api/facebook/sync-status/[jobId]`

Get the status of a sync job.

**Authentication:** Required  
**Rate Limit:** Standard (100/min)

**Path Parameters:**
- `jobId`: Sync job ID

**Response:**
```json
{
  "jobId": "sync-job-id",
  "status": "processing",
  "progress": 50,
  "totalContacts": 100,
  "syncedContacts": 50,
  "errors": [],
  "startedAt": "2025-01-27T10:00:00Z",
  "completedAt": null
}
```

**Status Codes:**
- `200`: Success
- `401`: Unauthorized
- `404`: Job not found
- `500`: Server error

---

## Error Responses

### Standard Error Format

All error responses follow this format:

```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

### HTTP Status Codes

| Code | Meaning | Common Causes |
|------|---------|----------------|
| `200` | Success | - |
| `400` | Bad Request | Invalid request body, missing required fields |
| `401` | Unauthorized | No session, expired session, invalid token |
| `403` | Forbidden | Insufficient permissions, missing organization |
| `404` | Not Found | Resource doesn't exist or doesn't belong to user |
| `409` | Conflict | Concurrent modification, duplicate entry |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Database error, unexpected exception |
| `503` | Service Unavailable | Database deadlock, temporary unavailability |

### Error Codes

| Code | Meaning | HTTP Status |
|------|---------|-------------|
| `UNAUTHORIZED` | Authentication required | 401 |
| `FORBIDDEN` | Insufficient permissions | 403 |
| `NOT_FOUND` | Resource not found | 404 |
| `CONCURRENT_MODIFICATION` | Resource modified by another request | 409 |
| `RATE_LIMIT_EXCEEDED` | Too many requests | 429 |
| `VALIDATION_ERROR` | Invalid input data | 400 |
| `DEADLOCK` | Database deadlock | 503 |

### Example Error Responses

**Unauthorized:**
```json
{
  "error": "Unauthorized"
}
```

**Not Found:**
```json
{
  "error": "Contact not found"
}
```

**Concurrent Modification:**
```json
{
  "error": "Contact was modified by another request. Please refresh and try again.",
  "code": "CONCURRENT_MODIFICATION"
}
```

**Rate Limit Exceeded:**
```json
{
  "error": "Too many requests. Please limit to 100 requests per minute.",
  "retryAfter": 30
}
```

---

## Rate Limiting

### Rate Limit Headers

All responses include rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
Retry-After: 30
```

### Rate Limit Presets

| Preset | Limit | Window | Used For |
|--------|-------|--------|----------|
| Strict | 10 | 1 minute | Sensitive operations, sync jobs |
| Standard | 100 | 1 minute | Most API endpoints (default) |
| Generous | 1000 | 1 minute | Read-heavy endpoints |
| Auth | 5 | 1 minute | Authentication endpoints |
| File Upload | 10 | 1 minute | File upload endpoints |

### Rate Limit Response

When rate limit is exceeded:

**Status Code:** `429 Too Many Requests`

**Response:**
```json
{
  "error": "Too many requests. Please limit to 100 requests per minute.",
  "retryAfter": 30
}
```

**Headers:**
```
Retry-After: 30
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640995200
```

---

## Additional Notes

### Request Validation

- All UUID/CUID parameters are validated
- Request body size is validated (limits vary by endpoint)
- Numeric inputs are validated (ranges, types)
- Required fields are checked

### Concurrent Updates

- Endpoints that support optimistic locking accept `expectedUpdatedAt`
- Returns `409 Conflict` if resource was modified
- Client should refresh and retry on conflict

### Pagination

- Default page size: 50
- Maximum page size: 100
- Cursor-based pagination available for some endpoints

### Caching

- Some GET endpoints use HTTP caching
- Cache-Control headers indicate cacheability
- React Query provides client-side caching

---

*Last Updated: 2025-01-27*









