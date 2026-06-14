const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
  getHardwareId:   () => ipcRenderer.invoke('license:get-hwid'),
  checkLicense:    () => ipcRenderer.invoke('license:check'),
  activateLicense: (key) => ipcRenderer.invoke('license:activate', key),
  saveBackup:      (data) => ipcRenderer.invoke('save-backup', data),
  loadBackup:      () => ipcRenderer.invoke('load-backup'),
  savePdf:         (data) => ipcRenderer.invoke('save-pdf', data),
  saveCsv:         (data) => ipcRenderer.invoke('save-csv', data),
  saveJson:        (data) => ipcRenderer.invoke('save-json', data),
  quit:            () => ipcRenderer.send('app:quit'),
  onLicenseExpired:(cb) => ipcRenderer.on('license:expired', cb),
});
