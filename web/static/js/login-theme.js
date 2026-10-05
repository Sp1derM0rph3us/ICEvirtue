
        (function () {
            try {
                var saved = localStorage.getItem('icevirtue-theme');
                var prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
                document.documentElement.dataset.theme =
                    saved === 'light' || saved === 'dark' ? saved : (prefersLight ? 'light' : 'dark');
            } catch (e) {
                document.documentElement.dataset.theme = 'dark';
            }
        })();
    
