# VEPT-EWO Management System

A web-based EWO (Engineering Work Order) management system for VEPT, designed to streamline the process of creating, managing, and tracking engineering work orders.

## Features

- Multi-role access (Production, Maintenance, Admin, Administrator)
- EWO creation and management
- Oil consumption tracking
- Why-Why analysis
- Export functionality for reports
- Mobile-responsive design

## Tech Stack

- Python 3.10+
- Flask web framework
- SQLAlchemy ORM
- PostgreSQL database
- Bootstrap 5 for UI
- Pandas for data processing

## Deployment

This application is deployed on Render.com. To deploy your own instance:

1. Create a Render account at https://render.com
2. Create a new Web Service
3. Connect your GitHub repository
4. Configure the following:
   - Name: vept-ewo
   - Environment: Python 3
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

### Environment Variables

Set these in your Render dashboard:
- `SECRET_KEY`: Your secret key for Flask sessions
- `DATABASE_URL`: Your PostgreSQL database URL (provided by Render)

## Local Development

1. Clone the repository
```bash
git clone https://github.com/yourusername/vept-ewo.git
cd vept-ewo
```

2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Set environment variables
```bash
export SECRET_KEY=your-secret-key
export DATABASE_URL=sqlite:///ewo.db
```

5. Run the application
```bash
python app.py
```

## Database Setup

The application will automatically create tables when first run. To create an admin user:

```bash
python create_users.py
```

## License

Proprietary - All rights reserved
