
    // The return position is read from sessionStorage, which is per-tab and same-origin, so
    // a link from an attacker's page cannot seed it. The server never sees or reflects it,
    // which is what keeps this from being an open redirect: the only thing appended to "/"
    // is a value proved to be a query string.
    const RETURN_KEY = 'icevirtue-return';
    const SAFE_QUERY = /^\?[^/\\:#]*$/;

    function toggleTheme() {
        const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
        document.documentElement.dataset.theme = next;
        try { localStorage.setItem('icevirtue-theme', next); } catch (e) {}
    }

    function returnTarget() {
        let q = '';
        try {
            q = sessionStorage.getItem(RETURN_KEY) || '';
            sessionStorage.removeItem(RETURN_KEY);
        } catch (e) {}
        return SAFE_QUERY.test(q) ? '/' + q : '/';
    }

    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const submitBtn = document.getElementById('submit-btn');
        const spinner = document.getElementById('spinner');
        const errorMsg = document.getElementById('error-msg');

        submitBtn.classList.add('hidden');
        spinner.classList.remove('hidden');
        errorMsg.classList.add('hidden');

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (res.ok) {
                window.location.replace(returnTarget()); 
            } else {
                errorMsg.textContent = 'Sign in failed. Check your credentials.';
                errorMsg.classList.remove('hidden');
                submitBtn.classList.remove('hidden');
                spinner.classList.add('hidden');
            }
        } catch (err) {
            errorMsg.textContent = 'Connection unavailable. Please try again.';
            errorMsg.classList.remove('hidden');
            submitBtn.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    });

