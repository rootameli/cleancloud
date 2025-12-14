// Runtime configuration for CleanCloud UI
// This file is loaded before script.js to provide environment-specific overrides
window.CLEAN_CLOUD_CONFIG = {
    apiBase: '/api/v1',
    healthEndpoint: '/api/v1/healthz',
    readyEndpoint: '/api/v1/readyz',
    stateStorageKey: 'cleanCloudAppState',
    enableDebug: true
};
