import { useState, useEffect } from 'react';

const STORAGE_KEY = 'patchpilot_owner_token';

function generateToken() {
  return crypto.randomUUID ? crypto.randomUUID() : 
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
}

export default function useOwnerToken() {
  const [token] = useState(() => {
    let stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) {
      stored = generateToken();
      localStorage.setItem(STORAGE_KEY, stored);
    }
    return stored;
  });

  return token;
}
