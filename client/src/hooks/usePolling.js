import { useEffect, useRef } from 'react';

export default function usePolling(callback, interval, enabled = true) {
  const savedCallback = useRef(callback);

  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  useEffect(() => {
    if (!enabled) return;
    
    const tick = () => savedCallback.current();
    tick(); // Run immediately
    const id = setInterval(tick, interval);
    return () => clearInterval(id);
  }, [interval, enabled]);
}
