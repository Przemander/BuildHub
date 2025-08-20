import AxiosInstance from '../config/axios';
import { ref, type Ref } from 'vue';
import { useRouter } from "vue-router";
import type { LoginFormInterface, RegistrationFormInterface } from '@/types';

const isAuthenticated: Ref<boolean> = ref(false);
const userData: Ref<null> = ref(null);

export function useAuthentication() {

  const router = useRouter();

  const login = async (formData: LoginFormInterface): Promise<void> => {
    try {
      await AxiosInstance.post('/login', { ...formData });
      isAuthenticated.value = true;
      router.push({ name: "UserDashboard" });
    } catch (error) {
      isAuthenticated.value = false;
      console.log(error);
      throw error;
    }
  }

  const getUser = async () => {
    try {
      const response = (await AxiosInstance.get('/user', {
        suppressGlobalError: true,
      })).data;
      isAuthenticated.value = true;
      userData.value = response;
      return response;
    } catch (error) {
      isAuthenticated.value = false;
      userData.value = null;
      console.log(error);
    }
  }

  const register = async (formData: RegistrationFormInterface): Promise<void> => {
    try {
      await AxiosInstance.post('/register', { ...formData });
    } catch (error) {
      console.log(error);
      throw error;
    }
  }

  const logOut = async (): Promise<void> => {
    try {
      await AxiosInstance.post('/logout');
      isAuthenticated.value = false;
      router.push({ name: "login" });
      userData.value = null;
    } catch (error) {
      console.log(error);
      throw error;
    }
  }

  return {
    login,
    register,
    logOut,
    getUser,
    isAuthenticated,
    userData,
  }
}
