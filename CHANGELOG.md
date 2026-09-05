# Changelog

## [0.2.0] - 2026-09-05

### Added
- API key authentication
- Request rate limiting with `429` responses and `Retry-After`
- CORS protection for the dashboard
- Security response headers
- Actor listing endpoint
- Secure Next.js dashboard API proxy
- GitHub Actions CI workflow
- Complete Python dependency manifest
- HTTP-level rate-limit regression tests
- Fresh-environment installation coverage

### Improved
- Proof and actor query performance
- SDK API-key handling
- Verification and security regression coverage
- CI support for API integration tests

### Security
- Protected API endpoints with `X-API-Key`
- Dashboard API credentials kept server-side
- Added browser security headers
- Added configurable request rate limiting
