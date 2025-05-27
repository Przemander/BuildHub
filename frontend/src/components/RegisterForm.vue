<template>
  <div class="register-form">
    <h2>Register</h2>
    <form @submit.prevent="handleRegister">
      <div class="form-group">
        <label for="username">Username:</label>
        <input 
          type="text" 
          id="username" 
          v-model="username" 
          required
        />
      </div>
      
      <div class="form-group">
        <label for="email">Email:</label>
        <input 
          type="email" 
          id="email" 
          v-model="email" 
          required
        />
      </div>
      
      <div class="form-group">
        <label for="password">Password:</label>
        <input 
          type="password" 
          id="password" 
          v-model="password" 
          required
        />
      </div>
      
      <button type="submit" :disabled="isLoading">
        {{ isLoading ? 'Registering...' : 'Register' }}
      </button>
      
      <p v-if="error" class="error">{{ error }}</p>
      <p v-if="success" class="success">{{ success }}</p>
    </form>
  </div>
</template>

<script>
import { ref } from 'vue';
import authService from '../services/authService';

export default {
  name: 'RegisterForm',
  setup() {
    // Create reactive variables
    const username = ref('');
    const email = ref('');
    const password = ref('');
    const error = ref('');
    const success = ref('');
    const isLoading = ref(false);
    
    // Function to handle form submission
    const handleRegister = async () => {
      error.value = '';
      success.value = '';
      isLoading.value = true;
      
      try {
        // We're now using the response variable
        await authService.register(
          username.value, 
          email.value, 
          password.value
        );
        
        // Registration successful
        success.value = 'Registration successful! You can now login.';
        
        // Clear the form
        username.value = '';
        email.value = '';
        password.value = '';
      } catch (err) {
        // Handle error
        error.value = err.response?.data?.message || 'Registration failed. Please try again.';
      } finally {
        isLoading.value = false;
      }
    };
    
    // Return values to make them available in the template
    return {
      username,
      email,
      password,
      error,
      success,
      isLoading,
      handleRegister
    };
  }
}
</script>

<style scoped>
.register-form {
  max-width: 400px;
  margin: 0 auto;
  padding: 20px;
  border: 1px solid #ccc;
  border-radius: 5px;
}

.form-group {
  margin-bottom: 15px;
}

label {
  display: block;
  margin-bottom: 5px;
}

input {
  width: 100%;
  padding: 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
}

button {
  background-color: #4CAF50;
  color: white;
  padding: 10px 15px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  margin-top: 10px;
}

button:disabled {
  background-color: #cccccc;
}

.error {
  color: red;
  font-size: 14px;
}

.success {
  color: green;
  font-size: 14px;
}
</style>