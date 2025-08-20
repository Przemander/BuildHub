import { ref, type Ref } from 'vue';
import { useLocalStorage } from './useLocalStorage';

const theme: Ref<'light' | 'dark'> = ref('dark');

export function useTheme() {

  const { save, get } = useLocalStorage();

  const toggle = (): void => {
    const newTheme = theme.value == 'light' ? 'dark' : 'light';
    theme.value = newTheme;
    save('theme', newTheme);
  }

  const fillFromStorage = (): void => {
    const themeFromStorage = get('theme');
    if (themeFromStorage === 'light' || themeFromStorage === 'dark') {
      theme.value = themeFromStorage;
    };
  }

  return {
    theme,
    toggle,
    fillFromStorage
  }
}