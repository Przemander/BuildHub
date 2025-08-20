// src/axios.d.ts
import 'axios';

declare module 'axios' {
  export interface AxiosRequestConfig {
    suppressGlobalError?: boolean;
  }
}
