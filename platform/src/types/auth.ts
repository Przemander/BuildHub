export interface RegistrationFormInterface {
  email: string|null,
  password: string|null,
  password_confirmation: string|null,
  recaptcha_token: string|null
}

export interface LoginFormInterface {
  email: string|null,
  password: string|null
}

export interface ForgotPasswordFormInterface {
  email: string | null,
  recaptcha_token: string | null,
}

export interface ResetPasswordFormInterface {
  email: string | null,
  password: string | null,
  password_confirmation: string | null,
  token: string,
}