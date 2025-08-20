import { createRouter, createWebHistory } from 'vue-router'
import { useAuthentication } from '../composables/useAuthentication';
import UserDashboardView from '../views/UserDashboardView.vue';
import MainDashboardView from '../views/MainDashboardView.vue';
import AdvertisementView from '../views/AdvertisementView.vue';
import RegistrationView from '../views/RegistrationView.vue'
import AboutView from '../views/AboutView.vue';
import ResetPasswordView from '@/views/ResetPasswordView.vue';
import NotFoundView from '@/views/NotFoundView.vue';

const router = createRouter({
  history: createWebHistory('/'),
  routes: [
    {
      path: '/register',
      name: 'registration',
      component: RegistrationView,
      meta: {
        isAuth: false,
      }
    },
    {
      path: '/about',
      name: 'about',
      component: AboutView,
      meta: {
        isAuth: false,
      }
    },
    {
      path: '/dashboard',
      name: 'dashboard',
      component: UserDashboardView,
      meta: {
        isAuth: true,
      }
    },
    {
      path: '/',
      name: 'main',
      component: MainDashboardView,
      meta: {
        isAuth: false,
      }
    },
    {
      path: '/advertise/:advertise',
      name: 'advertise',
      component: AdvertisementView,
      meta: {
        isAuth: false,
      }
    },
    {
      path: '/reset-password',
      name: 'resetPassword',
      component: ResetPasswordView,
      meta: {
        isAuth: false,
      }
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'NotFound',
      component: NotFoundView,
      meta: {
        isAuth: false,
      }
    }
  ]
});

router.beforeEach(async (to, from, next) => {
  const { isAuthenticated, getUser } = useAuthentication();

  await getUser();

  if (to.meta.isAuth && !isAuthenticated.value) {
    next('/');
  }

  if (to.name === 'login' && isAuthenticated.value) {
    next('/files')
  }
  return next();
})

export default router
