import axios from 'axios';
import router from '@/router';
import { useSnackbar } from '@/composables/useSnackbar';
import { extractErrorMessage } from '@/plugins/helpers';

const AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' },
  withCredentials: true,
  withXSRFToken: true,
});

AxiosInstance.interceptors.response.use(
  response => response,
  async error => {
    const { setNotification } = useSnackbar();
    const config = error.config || {};
    const code = error?.response?.data?.code;

    //obsługa tokenów csrf - mozna dorobić na backendzie
    if (code === 'CSRF_TOKEN_MISMATCH') {
      await AxiosInstance.get('/auth/csrf-cookie');
    }

    if (code === 'AUTH_SESSION_EXPIRED') {
      await AxiosInstance.get('/auth/csrf-cookie');
      router.replace('/');
    }
    //

    if (!config.suppressGlobalError) {
      const message = extractErrorMessage(error, "Wystąpił nieoczekiwany błąd. Spróbuj ponownie później.")
      setNotification(message);
    }

    return Promise.reject(error);
  }
);

export default AxiosInstance;
