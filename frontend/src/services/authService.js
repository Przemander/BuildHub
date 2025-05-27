import apiClient from './apiClient';

// Service for authentication-related API calls
export default {
  // Register function
  register(username, email, password) {
    return apiClient.post('/auth/register', { username, email, password });
  }
};