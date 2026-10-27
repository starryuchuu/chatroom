import { contextBridge, ipcRenderer } from 'electron';
import { METHODS, type CoreEvent, type Method } from '../src/protocol';

contextBridge.exposeInMainWorld('chatroom', {
  platform: process.platform,
  request(method: Method, params: Record<string, unknown> = {}) {
    if (!METHODS.includes(method)) return Promise.reject(new Error('不支持的操作'));
    return ipcRenderer.invoke('core:request', method, params);
  },
  subscribe(callback: (event: CoreEvent) => void) {
    const listener = (_event: unknown, payload: CoreEvent) => callback(payload);
    ipcRenderer.on('core:event', listener);
    return () => ipcRenderer.removeListener('core:event', listener);
  },
  copy(text: string) { return ipcRenderer.invoke('clipboard:write', text); },
});
