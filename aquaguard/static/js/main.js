// AquaGuard Main JavaScript

// File upload preview
document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('file');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const fileName = this.files[0]?.name;
            if (fileName) {
                // Show file name in a small preview
                const filePreview = document.createElement('div');
                filePreview.classList.add('alert', 'alert-info', 'mt-2');
                filePreview.textContent = `Selected file: ${fileName}`;
                
                // Remove any existing preview
                const existingPreview = this.parentElement.querySelector('.alert');
                if (existingPreview) {
                    existingPreview.remove();
                }
                
                this.parentElement.appendChild(filePreview);
            }
        });
    }
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            const closeButton = alert.querySelector('.btn-close');
            if (closeButton) {
                closeButton.click();
            }
        }, 5000);
    });
});