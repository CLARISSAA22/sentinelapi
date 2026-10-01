// SentinelAPI Platform Core JavaScript

document.addEventListener('DOMContentLoaded', () => {
    initModals();
});

// Toast notification manager
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type === 'error' ? 'toast-error' : (type === 'success' ? 'toast-success' : '')}`;
    
    let iconName = 'alert-circle';
    let iconColor = 'var(--color-primary)';
    if (type === 'success') {
        iconName = 'check-circle';
        iconColor = 'var(--color-low)';
    } else if (type === 'error') {
        iconName = 'alert-triangle';
        iconColor = 'var(--color-critical)';
    }

    const iconSvg = typeof getIconSvg === 'function' 
        ? getIconSvg(iconName, 18, '', iconColor)
        : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>`;

    toast.innerHTML = `<span style="display: flex; align-items: center;">${iconSvg}</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-10px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Modal management
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function initModals() {
    // Backdrop click to close
    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
        backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) {
                backdrop.classList.remove('active');
                document.body.style.overflow = '';
            }
        });
    });

    // Close buttons
    document.querySelectorAll('[data-close-modal]').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalId = btn.getAttribute('data-close-modal');
            closeModal(modalId);
        });
    });
}

// Custom confirmation dialog (Never uses native window.confirm)
function confirmAction(title, message, confirmBtnText = 'Confirm', onConfirm) {
    let confirmModal = document.getElementById('sentinel-confirm-modal');
    if (!confirmModal) {
        confirmModal = document.createElement('div');
        confirmModal.id = 'sentinel-confirm-modal';
        confirmModal.className = 'modal-backdrop';
        confirmModal.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h3 class="modal-title" id="confirm-modal-title">Confirm Action</h3>
                </div>
                <div class="modal-body">
                    <p id="confirm-modal-msg" style="color: var(--text-secondary);"></p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('sentinel-confirm-modal')">Cancel</button>
                    <button type="button" class="btn btn-danger" id="confirm-modal-action-btn">Confirm</button>
                </div>
            </div>
        `;
        document.body.appendChild(confirmModal);
        initModals();
    }

    document.getElementById('confirm-modal-title').textContent = title;
    document.getElementById('confirm-modal-msg').textContent = message;
    
    const actionBtn = document.getElementById('confirm-modal-action-btn');
    actionBtn.textContent = confirmBtnText;
    
    // Clone button to remove previous listeners
    const newActionBtn = actionBtn.cloneNode(true);
    actionBtn.parentNode.replaceChild(newActionBtn, actionBtn);
    
    newActionBtn.addEventListener('click', () => {
        closeModal('sentinel-confirm-modal');
        if (typeof onConfirm === 'function') {
            onConfirm();
        }
    });

    openModal('sentinel-confirm-modal');
}

// Reusable fetch wrapper with error handling
async function apiRequest(url, options = {}) {
    const defaultHeaders = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    };

    options.headers = { ...defaultHeaders, ...(options.headers || {}) };

    try {
        const response = await fetch(url, options);
        const data = await response.json().catch(() => ({}));
        
        if (!response.ok) {
            throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
        }
        return data;
    } catch (error) {
        showToast(error.message, 'error');
        throw error;
    }
}
