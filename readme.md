# AI Session Hijacking Detector

An AI-powered Session Hijacking Detection System built using FastAPI, Machine Learning, and MySQL.

## Features

- User behavior learning (first 15 normal logins)
- Continuous learning from normal logins
- Rule-based risk analysis
- AI-based suspicious login detection
- Automatic risk scoring
- Session blocking and force re-login actions
- Alert generation for suspicious logins
- Manual AI model retraining endpoint
- Cloud MySQL database support (Aiven)
- Ready for deployment on Render
- Designed to integrate with a Spring Boot Admin Dashboard

## Technology Stack

- Python
- FastAPI
- Scikit-learn
- Pandas
- MySQL
- Aiven Cloud Database
- Render
- Git & GitHub

## API Endpoints

### Predict Login

```
POST /predict
```

Analyzes login requests and determines whether the login is:

- Learning
- Normal
- Suspicious

### Train AI Model

```
POST /train
```

Retrains the AI model using the latest login data.

## Project Workflow

```
User Login
      │
      ▼
FastAPI API
      │
      ▼
Rule Engine
      │
      ▼
AI Model
      │
      ▼
Risk Score
      │
      ▼
Allow / Force Re-login / Block Session
      │
      ▼
Store Results in MySQL
```

## Future Improvements

- Spring Boot Admin Dashboard
- User Analytics
- Login Heatmaps
- Email Alerts
- JWT Authentication
- Docker Deployment

## Author

Anukshan
BSc Cyber Security Undergraduate