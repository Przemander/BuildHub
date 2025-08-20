export function useLocalStorage(){
  const save = (key: string, value: string): void => {
    localStorage.setItem(key, value);  
  }
  const remove = (key: string): void => {
    localStorage.removeItem(key);
  }
  const get = (key: string): string|null => {
    return localStorage.getItem(key);
  }

  return {
    save,
    remove,
    get
  }
}