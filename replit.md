# Overview

This is a network host monitoring system built with Flask that provides real-time monitoring, IP access control, and user authentication. The application allows administrators to monitor network hosts organized in groups and subgroups, track ping history, visualize availability metrics, and control access through IP whitelisting/blacklisting mechanisms.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Template Engine**: Jinja2 templates with Bootstrap 5 for responsive UI
- **JavaScript**: Vanilla JavaScript with Chart.js for data visualization
- **CSS Framework**: Bootstrap 5 with custom CSS for status indicators and monitoring-specific styling
- **Real-time Updates**: Auto-refresh functionality for monitoring data every 5 minutes

## Backend Architecture
- **Framework**: Flask with SQLAlchemy ORM for data persistence  
- **Database**: SQLite as primary database with dynamic table creation for host groups
- **Authentication**: Flask-Dance integration with Replit Auth for OAuth authentication
- **Session Management**: Flask-Login for user session handling
- **Middleware**: ProxyFix for handling reverse proxy headers
- **Security**: SQL injection protection through parameterized queries and ORM usage
- **Local Dependencies**: All frontend libraries downloaded locally (Bootstrap 5, Chart.js, Font Awesome, Feather Icons)

## Security & Access Control
- **IP Filtering**: Dual-layer IP control system with whitelist and blacklist management via JSON files
- **Rate Limiting**: Automatic IP blocking after failed access attempts (3 strikes rule) with DDOS protection
- **Authentication**: OAuth-based authentication with role-based access control
- **Admin Privileges**: Separate admin interface for system management
- **Data Encryption**: HTTPS enforcement through ProxyFix middleware
- **SQL Injection Protection**: Parameterized queries and proper input sanitization

## Data Models
- **User Management**: Users with OAuth tokens and admin flags
- **Access Logging**: Complete audit trail of access attempts and system usage
- **IP Management**: Tracking of IP attempts, blocks, and access patterns
- **Dynamic Schema**: Host groups create separate tables for flexible monitoring organization

## Monitoring System
- **Host Organization**: Hierarchical structure with groups and subgroups
- **Ping Monitoring**: Historical ping data collection and analysis
- **Status Tracking**: Real-time availability and latency monitoring
- **Dashboard Visualization**: Charts and graphs for performance metrics

# External Dependencies

## Authentication Services
- **Replit Auth**: OAuth provider for user authentication
- **Flask-Dance**: OAuth client library for handling authentication flows

## Frontend Libraries
- **Bootstrap 5**: CSS framework loaded locally for consistent UI
- **Chart.js**: JavaScript charting library for data visualization
- **Font Awesome**: Icon library for UI elements
- **Feather Icons**: Additional icon set for interface elements

## Python Dependencies
- **Flask Ecosystem**: Core web framework with SQLAlchemy, Login, and Dance extensions
- **SQLite**: Embedded database for data persistence
- **JWT**: Token handling for authentication
- **Werkzeug**: WSGI utilities and middleware

## Configuration Management
- **JSON Configuration**: Whitelist and blacklist management through JSON files
- **Environment Variables**: Database URLs and session secrets
- **File-based Storage**: Local configuration files for IP access control

## Network Monitoring
- **Subprocess**: System ping command execution for network testing
- **Threading**: Background monitoring processes
- **SQLite Monitoring**: Separate monitoring database for ping history and metrics

# Recent Changes

## Date: 2025-08-08

### Latest Updates:
- **Network Interface Selection**: Restored original functionality to choose server interface
- **Database Migration**: Switched from PostgreSQL to SQLite for simplified deployment
- **Security Enhancements**: Added comprehensive SQL injection protection
- **Local Dependencies**: All frontend libraries now served locally (no CDN dependencies)
- **Test Data**: Created comprehensive test dataset with 10 hosts across 4 subgroups
- **UI Improvements**: Enhanced subgroup visualization with color-coded status indicators
- **Multiple Launch Options**: Added run_local.py and run_with_interface.py startup scripts

### Previous Implementations:
- Initial system setup with network host monitoring capabilities
- Implementation of hierarchical host organization (groups/subgroups)  
- Real-time ping monitoring with historical data collection
- Administrative interface for IP access control
- Integration with Replit Auth for secure user authentication
- IP whitelist/blacklist management with JSON configuration
- DDOS protection with automated IP blocking