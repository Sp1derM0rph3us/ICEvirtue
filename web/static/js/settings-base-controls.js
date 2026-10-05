document.querySelector('[data-click="settings_base-0"]').addEventListener('click', event => { toggleNotifPanel(event); });
document.querySelector('[data-click="settings_base-1"]').addEventListener('click', event => { deleteAllNotifs(); });
document.querySelector('[data-click="settings_base-2"]').addEventListener('click', event => { markAllNotifsRead(); });
