// Filesystem browser functionality
document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const currentPathElement = document.getElementById('current-path');
    const fileListElement = document.getElementById('file-list');
    const refreshButton = document.getElementById('refresh-btn');
    const uploadButton = document.getElementById('upload-btn');
    const uploadModal = document.getElementById('upload-modal');
    const closeModalButton = document.querySelector('.close');
    const cancelUploadButton = document.getElementById('cancel-upload');
    const uploadForm = document.getElementById('upload-form');
    const uploadPathInput = document.getElementById('upload-path');
    const filePreviewContainer = document.getElementById('file-preview-container');
    const previewContent = document.getElementById('preview-content');
    const closePreviewButton = document.getElementById('close-preview');
    const uploadStatus = document.getElementById('upload-status');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const uploadProgress = document.getElementById('upload-progress');
    
    // Current working directory
    let currentPath = currentPathElement.textContent;
    
    // Load files from the current directory
    function loadFiles(path) {
        fileListElement.innerHTML = '<tr><td colspan="4">Loading files...</td></tr>';
        
        fetch(`/api/files?path=${encodeURIComponent(path)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Update current path
                currentPath = data.path;
                currentPathElement.textContent = currentPath;
                
                // Clear file list
                fileListElement.innerHTML = '';
                
                if (data.files.length === 0) {
                    fileListElement.innerHTML = '<tr><td colspan="4">Directory is empty</td></tr>';
                    return;
                }
                
                // Add files to the table
                data.files.forEach(file => {
                    const row = document.createElement('tr');
                    row.className = file.isHidden ? 'hidden-file' : '';
                    
                    // Name column with icon
                    const nameCell = document.createElement('td');
                    nameCell.className = 'name-col';
                    
                    if (file.isDir) {
                        nameCell.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-folder directory-icon"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>${file.name}`;
                        nameCell.style.cursor = 'pointer';
                        nameCell.addEventListener('click', () => {
                            loadFiles(file.path);
                        });
                    } else {
                        nameCell.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-file file-icon"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>${file.name}`;
                    }
                    
                    // Size column
                    const sizeCell = document.createElement('td');
                    sizeCell.className = 'size-col';
                    sizeCell.textContent = file.isDir ? '--' : formatBytes(file.size);
                    
                    // Modified column
                    const modifiedCell = document.createElement('td');
                    modifiedCell.className = 'modified-col';
                    modifiedCell.textContent = file.modified || '--';
                    
                    // Actions column
                    const actionsCell = document.createElement('td');
                    actionsCell.className = 'actions-col';
                    
                    if (!file.isDir) {
                        // Download button
                        const downloadButton = document.createElement('button');
                        downloadButton.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-download"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>';
                        downloadButton.title = 'Download';
                        downloadButton.addEventListener('click', () => {
                            downloadFile(file.path);
                        });
                        
                        // Preview button
                        const previewButton = document.createElement('button');
                        previewButton.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-eye"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
                        previewButton.title = 'Preview';
                        previewButton.addEventListener('click', () => {
                            previewFile(file.path, file.name);
                        });
                        
                        actionsCell.appendChild(downloadButton);
                        actionsCell.appendChild(previewButton);
                    } else {
                        // Zip button for directories
                        const zipButton = document.createElement('button');
                        zipButton.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-archive"><polyline points="21 8 21 21 3 21 3 8"></polyline><rect x="1" y="3" width="22" height="5"></rect><line x1="10" y1="12" x2="14" y2="12"></line></svg>';
                        zipButton.title = 'Download as ZIP';
                        zipButton.addEventListener('click', () => {
                            zipDirectory(file.path);
                        });
                        
                        actionsCell.appendChild(zipButton);
                    }
                    
                    // Append cells to row
                    row.appendChild(nameCell);
                    row.appendChild(sizeCell);
                    row.appendChild(modifiedCell);
                    row.appendChild(actionsCell);
                    
                    // Append row to table
                    fileListElement.appendChild(row);
                });
                
                // Replace feather icons after adding to DOM
                feather.replace();
            })
            .catch(error => {
                console.error('Error loading files:', error);
                fileListElement.innerHTML = `<tr><td colspan="4">Error loading files: ${error.message}</td></tr>`;
            });
    }
    
    // Download a file
    function downloadFile(filePath) {
        window.location.href = `/api/file/download?path=${encodeURIComponent(filePath)}`;
        uploadStatus.textContent = `Downloading: ${filePath.split('/').pop()}`;
        setTimeout(() => {
            uploadStatus.textContent = '';
        }, 3000);
    }
    
    // Preview a file
    function previewFile(filePath, fileName) {
        const fileExt = fileName.split('.').pop().toLowerCase();
        const textExtensions = ['txt', 'log', 'md', 'go', 'py', 'js', 'html', 'css', 'json', 'xml', 'yml', 'yaml'];
        const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'svg'];
        
        // Show the preview container
        filePreviewContainer.style.display = 'block';
        previewContent.innerHTML = `<div class="no-preview">Loading preview...</div>`;
        
        // Fetch file for preview
        fetch(`/api/file/preview?path=${encodeURIComponent(filePath)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error ${response.status}`);
                }
                
                const contentType = response.headers.get('Content-Type');
                
                if (imageExtensions.includes(fileExt) || contentType.startsWith('image/')) {
                    return response.blob().then(blob => {
                        const url = URL.createObjectURL(blob);
                        previewContent.innerHTML = `<img src="${url}" style="max-width: 100%; max-height: 500px;" alt="${fileName}">`;
                    });
                } else if (textExtensions.includes(fileExt) || contentType === 'text/plain') {
                    return response.text().then(text => {
                        previewContent.innerHTML = `<pre style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(text)}</pre>`;
                    });
                } else {
                    previewContent.innerHTML = `<div class="no-preview">Cannot preview this file type</div>`;
                }
            })
            .catch(error => {
                previewContent.innerHTML = `<div class="no-preview">Error: ${error.message}</div>`;
            });
    }
    
    // ZIP a directory
    function zipDirectory(dirPath) {
        window.location.href = `/api/file/zip?path=${encodeURIComponent(dirPath)}`;
        uploadStatus.textContent = `Zipping: ${dirPath.split('/').pop()}`;
        setTimeout(() => {
            uploadStatus.textContent = '';
        }, 3000);
    }
    
    // Show upload modal
    function showUploadModal() {
        uploadPathInput.value = currentPath;
        uploadModal.style.display = 'block';
        uploadForm.style.display = 'block';
        uploadProgress.style.display = 'none';
        progressFill.style.width = '0%';
        progressText.textContent = '0%';
    }
    
    // Hide upload modal
    function hideUploadModal() {
        uploadModal.style.display = 'none';
    }
    
    // Upload file
    function uploadFile(formData) {
        uploadForm.style.display = 'none';
        uploadProgress.style.display = 'block';
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/file/upload', true);
        
        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                progressFill.style.width = percentComplete + '%';
                progressText.textContent = percentComplete + '%';
            }
        };
        
        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    uploadStatus.textContent = response.message;
                    setTimeout(() => {
                        uploadStatus.textContent = '';
                    }, 3000);
                    hideUploadModal();
                    loadFiles(currentPath);
                } catch (e) {
                    console.error('Error parsing response:', e);
                    uploadStatus.textContent = 'Upload completed but encountered an error';
                    hideUploadModal();
                }
            } else {
                uploadStatus.textContent = `Upload failed: ${xhr.statusText}`;
                console.error('Upload failed:', xhr.statusText);
            }
        };
        
        xhr.onerror = function() {
            uploadStatus.textContent = 'Upload failed: Network error';
            console.error('Upload failed: Network error');
        };
        
        xhr.send(formData);
    }
    
    // Escape HTML to prevent XSS
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    // Format bytes to human-readable format
    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
    
    // Event listeners
    refreshButton.addEventListener('click', () => {
        loadFiles(currentPath);
    });
    
    uploadButton.addEventListener('click', showUploadModal);
    
    closeModalButton.addEventListener('click', hideUploadModal);
    
    cancelUploadButton.addEventListener('click', hideUploadModal);
    
    closePreviewButton.addEventListener('click', () => {
        filePreviewContainer.style.display = 'none';
    });
    
    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        uploadFile(formData);
    });
    
    // Close modal when clicking outside
    window.addEventListener('click', function(e) {
        if (e.target === uploadModal) {
            hideUploadModal();
        }
    });
    
    // Initial file load
    loadFiles(currentPath);
});
