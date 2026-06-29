# Internal Server Notes

## Server: corp-webapp-01
- Web application accessible at http://corp-webapp-01.internal:8080
- Admin panel at /admin (requires login)
- Backup service at /admin/backup
- File manager at /admin/files

## Credentials
See .env file for current credentials.

## Maintenance Log
2026-06-15: Updated web application to v2.4.1
2026-06-18: Added backup service with AWS integration
2026-06-22: Patched user search API (still has some issues with special characters)
2026-06-25: DevOps team requested file upload feature for deployment scripts