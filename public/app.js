const API_URL = window.location.origin + '/api';
let currentUser = null;
let currentVideo = null;
let isLoginMode = true;

// Check if user is logged in
const token = localStorage.getItem('token');
if (token) {
    fetchUserData();
}

// Fetch user data
async function fetchUserData() {
    try {
        const response = await fetch(`${API_URL}/auth/me`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        if (response.ok) {
            const data = await response.json();
            currentUser = data.user;
            updateUIForUser();
        } else {
            localStorage.removeItem('token');
        }
    } catch (error) {
        console.error('Error fetching user:', error);
    }
}

// Update UI based on user
function updateUIForUser() {
    if (currentUser) {
        document.getElementById('authText').textContent = 'Logout';
        document.getElementById('authLink').onclick = logout;
        
        if (currentUser.role === 'admin' || currentUser.role === 'super_admin') {
            document.getElementById('uploadLink').style.display = 'inline';
            document.getElementById('adminLink').style.display = 'inline';
        }
    }
}

// Toggle auth
function toggleAuth() {
    const container = document.getElementById('authContainer');
    container.style.display = container.style.display === 'none' ? 'block' : 'none';
    document.getElementById('videoContainer').style.display = 'none';
}

// Toggle auth mode (login/register)
function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    document.getElementById('authTitle').textContent = isLoginMode ? 'Login' : 'Register';
    document.getElementById('authSubmit').textContent = isLoginMode ? 'Login' : 'Register';
    document.getElementById('toggleAuthText').textContent = isLoginMode ? "Don't have an account?" : "Already have an account?";
    document.getElementById('toggleAuthLink').textContent = isLoginMode ? 'Register' : 'Login';
    document.getElementById('heardFrom').style.display = isLoginMode ? 'none' : 'block';
}

// Handle authentication
async function handleAuth(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const secretCode = document.getElementById('secretCode').value;
    const heardFrom = document.getElementById('heardFrom').value;

    try {
        const endpoint = isLoginMode ? '/auth/login' : '/auth/register';
        const response = await fetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, secretCode, heardFrom })
        });

        const data = await response.json();
        if (response.ok) {
            localStorage.setItem('token', data.token);
            currentUser = data.user;
            document.getElementById('authContainer').style.display = 'none';
            document.getElementById('videoContainer').style.display = 'block';
            updateUIForUser();
            loadVideos();
            alert('Authentication successful!');
        } else {
            alert(data.error || 'Authentication failed');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Logout
function logout() {
    localStorage.removeItem('token');
    currentUser = null;
    document.getElementById('authText').textContent = 'Login';
    document.getElementById('authLink').onclick = toggleAuth;
    document.getElementById('uploadLink').style.display = 'none';
    document.getElementById('adminLink').style.display = 'none';
    loadVideos();
}

// Load videos
async function loadVideos() {
    try {
        const response = await fetch(`${API_URL}/videos`);
        const videos = await response.json();
        displayVideos(videos);
    } catch (error) {
        console.error('Error loading videos:', error);
    }
}

// Display videos
function displayVideos(videos) {
    const grid = document.getElementById('videoGrid');
    if (videos.length === 0) {
        grid.innerHTML = '<p style="text-align:center;font-size:1.2rem;">No videos uploaded yet. Be the first!</p>';
        return;
    }
    
    grid.innerHTML = videos.map(video => `
        <div class="video-card" onclick="playVideo(${video.id})">
            <img src="${video.thumbnail_url || '/default-thumbnail.jpg'}" 
                 alt="${video.title}" 
                 class="video-thumbnail"
                 onerror="this.src='/default-thumbnail.jpg'">
            <div class="video-info">
                <div class="video-title">${video.title}</div>
                <div class="video-meta">
                    ${video.uploader_name} • ${video.views} views • 
                    ${new Date(video.created_at).toLocaleDateString()}
                </div>
            </div>
        </div>
    `).join('');
}

// Play video
async function playVideo(videoId) {
    try {
        const response = await fetch(`${API_URL}/videos/${videoId}`);
        const data = await response.json();
        currentVideo = data;
        
        const player = document.getElementById('videoPlayer');
        player.style.display = 'flex';
        
        const video = document.getElementById('mainVideo');
        video.src = data.video_url;
        video.controls = true;
        
        document.getElementById('videoTitle').textContent = data.title;
        document.getElementById('videoDescription').textContent = data.description || 'No description';
        document.getElementById('likeCount').textContent = data.likes || 0;
        document.getElementById('dislikeCount').textContent = data.dislikes || 0;
        
        displayComments(data.comments || []);
    } catch (error) {
        alert('Error loading video: ' + error.message);
    }
}

// Close player
function closePlayer() {
    document.getElementById('videoPlayer').style.display = 'none';
    const video = document.getElementById('mainVideo');
    video.pause();
    video.src = '';
}

// Like video
async function likeVideo() {
    if (!currentUser) {
        alert('Please login to like videos');
        return;
    }
    try {
        const response = await fetch(`${API_URL}/videos/${currentVideo.id}/like`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ action: 'like' })
        });
        if (response.ok) {
            const count = parseInt(document.getElementById('likeCount').textContent) + 1;
            document.getElementById('likeCount').textContent = count;
            alert('Video liked!');
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to like');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Dislike video
async function dislikeVideo() {
    if (!currentUser) {
        alert('Please login to dislike videos');
        return;
    }
    try {
        const response = await fetch(`${API_URL}/videos/${currentVideo.id}/like`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ action: 'dislike' })
        });
        if (response.ok) {
            const count = parseInt(document.getElementById('dislikeCount').textContent) + 1;
            document.getElementById('dislikeCount').textContent = count;
            alert('Video disliked!');
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to dislike');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Share video
async function shareVideo() {
    const url = window.location.origin + '/video/' + currentVideo.id;
    if (navigator.share) {
        try {
            await navigator.share({
                title: currentVideo.title,
                text: 'Watch this amazing video on AKABAKUZE!',
                url: url
            });
            // Record share
            await fetch(`${API_URL}/videos/${currentVideo.id}/share`, { method: 'POST' });
        } catch (error) {
            if (error.name !== 'AbortError') {
                copyLink();
            }
        }
    } else {
        copyLink();
    }
}

// Copy link
function copyLink() {
    const url = window.location.origin + '/video/' + currentVideo.id;
    navigator.clipboard.writeText(url).then(() => {
        alert('Link copied to clipboard!');
        // Record share
        fetch(`${API_URL}/videos/${currentVideo.id}/share`, { method: 'POST' });
    }).catch(() => {
        prompt('Copy this link:', url);
    });
}

// Download video
function downloadVideo() {
    const link = document.createElement('a');
    link.href = currentVideo.video_url;
    link.download = currentVideo.title + '.mp4';
    link.click();
}

// Add comment
async function addComment() {
    if (!currentUser) {
        alert('Please login to comment');
        return;
    }
    const input = document.getElementById('commentInput');
    const comment = input.value.trim();
    if (!comment) {
        alert('Please enter a comment');
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/videos/${currentVideo.id}/comment`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ comment })
        });
        
        if (response.ok) {
            const data = await response.json();
            input.value = '';
            displayComments([data.comment, ...(currentVideo.comments || [])]);
            alert('Comment added!');
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to add comment');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Display comments
function displayComments(comments) {
    const list = document.getElementById('commentsList');
    if (!comments || comments.length === 0) {
        list.innerHTML = '<p>No comments yet. Be the first!</p>';
        return;
    }
    list.innerHTML = comments.map(comment => `
        <div class="comment">
            <div class="comment-username">${comment.username}</div>
            <div>${comment.comment}</div>
            <small>${new Date(comment.created_at).toLocaleString()}</small>
        </div>
    `).join('');
}

// Upload video
async function uploadVideo(e) {
    e.preventDefault();
    if (!currentUser || !['admin', 'super_admin'].includes(currentUser.role)) {
        alert('Only admins can upload videos');
        return;
    }
    
    const formData = new FormData();
    formData.append('title', document.getElementById('videoTitleInput').value);
    formData.append('description', document.getElementById('videoDescriptionInput').value);
    formData.append('video', document.getElementById('videoFile').files[0]);
    formData.append('thumbnail', document.getElementById('thumbnailFile').files[0]);
    
    try {
        const response = await fetch(`${API_URL}/videos/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: formData
        });
        
        if (response.ok) {
            alert('Video uploaded successfully!');
            document.getElementById('uploadForm').reset();
            loadVideos();
        } else {
            const data = await response.json();
            alert(data.error || 'Upload failed');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Show admin dashboard
async function showAdmin() {
    if (!currentUser || !['admin', 'super_admin'].includes(currentUser.role)) {
        alert('Access denied');
        return;
    }
    
    document.getElementById('videoContainer').style.display = 'none';
    document.getElementById('uploadContainer').style.display = 'none';
    document.getElementById('joinUsContainer').style.display = 'none';
    document.getElementById('adminContainer').style.display = 'block';
    
    try {
        const response = await fetch(`${API_URL}/admin/stats`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        const data = await response.json();
        
        const statsHtml = `
            <div class="stat-card">
                <div class="stat-number">${data.stats.total_visits || 0}</div>
                <div>Total Visits</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${data.userCount || 0}</div>
                <div>Total Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${data.videoCount || 0}</div>
                <div>Total Videos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${data.stats.total_views || 0}</div>
                <div>Total Views</div>
            </div>
        `;
        document.getElementById('adminStats').innerHTML = statsHtml;
        
        const logsHtml = data.recentLogs.map(log => `
            <div class="log-entry">
                <strong>${log.username || 'Unknown'}</strong> - 
                ${log.action} - ${new Date(log.created_at).toLocaleString()}
            </div>
        `).join('');
        document.getElementById('adminLogs').innerHTML = `
            <h3>Recent Activity</h3>
            ${logsHtml || 'No logs available'}
        `;
    } catch (error) {
        alert('Error loading admin data: ' + error.message);
    }
}

// Create admin
async function createAdmin(e) {
    e.preventDefault();
    if (!currentUser || currentUser.role !== 'super_admin') {
        alert('Only super admin can create admins');
        return;
    }
    
    const username = document.getElementById('newAdminUsername').value;
    const password = document.getElementById('newAdminPassword').value;
    
    try {
        const response = await fetch(`${API_URL}/admin/create-admin`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ username, password })
        });
        
        if (response.ok) {
            alert('Admin created successfully!');
            document.getElementById('newAdminUsername').value = '';
            document.getElementById('newAdminPassword').value = '';
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to create admin');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Show home
function showHome() {
    document.getElementById('videoContainer').style.display = 'block';
    document.getElementById('uploadContainer').style.display = 'none';
    document.getElementById('adminContainer').style.display = 'none';
    document.getElementById('joinUsContainer').style.display = 'none';
    document.getElementById('videoPlayer').style.display = 'none';
    loadVideos();
}

// Show upload
function showUpload() {
    if (!currentUser || !['admin', 'super_admin'].includes(currentUser.role)) {
        alert('Access denied');
        return;
    }
    document.getElementById('videoContainer').style.display = 'none';
    document.getElementById('uploadContainer').style.display = 'block';
    document.getElementById('adminContainer').style.display = 'none';
    document.getElementById('joinUsContainer').style.display = 'none';
}

// Show join us
function showJoinUs() {
    document.getElementById('videoContainer').style.display = 'none';
    document.getElementById('uploadContainer').style.display = 'none';
    document.getElementById('adminContainer').style.display = 'none';
    document.getElementById('joinUsContainer').style.display = 'block';
}

// Request pro account
function requestProAccount() {
    if (!currentUser) {
        alert('Please login first');
        return;
    }
    alert('Thank you for your interest! An admin will review your request and contact you soon.');
}

// Social share functions
function shareToFacebook() {
    const url = window.location.href;
    window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(url)}`, '_blank');
}

function shareToTwitter() {
    const url = window.location.href;
    const text = 'Check out AKABAKUZE - The best video sharing platform!';
    window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`, '_blank');
}

function shareToWhatsApp() {
    const url = window.location.href;
    window.open(`https://wa.me/?text=${encodeURIComponent('Check out AKABAKUZE: ' + url)}`, '_blank');
}

// Show trending (similar to home)
function showTrending() {
    showHome();
}

// Initialize
loadVideos();

// Check for video ID in URL
const urlParams = new URLSearchParams(window.location.search);
const videoId = urlParams.get('v');
if (videoId) {
    setTimeout(() => playVideo(videoId), 500);
}

console.log('AKABAKUZE loaded successfully!');
