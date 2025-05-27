import axios from 'axios';

// Simple API client to connect to your backend
const apiClient = axios.create({
  baseURL: 'http://localhost:3000', // Your backend URL
  headers: {
    'Content-Type': 'application/json'
  }
});

export default apiClient;