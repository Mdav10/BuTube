const API_URL = window.location.origin + '/api';
let currentUser = null;
let currentVideo = null;
let isLoginMode = true;

// Check if user is logged in
const token = localStorage.getItem('token');
if (token) {
    fetchUserData();
}

async function fetchUserData() {
    try {
        const response = await fetch(`${API_URL}/auth/me`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
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

function toggleAuth() {
    const container = document.getElementById('authContainer');
    container.style.display = container.style.display === 'none' ? 'block' : 'none';
    document.getElementById('videoContainer').style.display = 'none';
}

function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    document.getElementById('authTitle').textContent = isLoginMode ? 'Login' : 'Register';
    document.getElementById('authSubmit').textContent = isLoginMode ? 'Login' : 'Register';
    document.getElementById('toggleAuthText').textContent = isLoginMode ? "Don't have an account?" : "Already have an account?";
    document.getElementById('toggleAuthLink').textContent = isLoginMode ? 'Register' : 'Login';
    document.getElementById('heardFrom').style.display = isLoginMode ? 'none' : 'block';
}

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
            alert('✅ Authentication successful!');
        } else {
            alert('❌ ' + (data.error || 'Authentication failed'));
        }
    } catch (error) {
        alert('❌ Error: ' + error.message);
    }
}

function logout() {
    localStorage.removeItem('token');
    currentUser = null;
    document.getElementById('authText').textContent = 'Login';
    document.getElementById('authLink').onclick = toggleAuth;
    document.getElementById('uploadLink').style.display = 'none';
    document.getElementById('adminLink').style.display = 'none';
    loadVideos();
}

async function loadVideos() {
    try {
        const response = await fetch(`${API_URL}/videos`);
        const videos = await response.json();
        displayVideos(videos);
    } catch (error) {
        console.error('Error loading videos:', error);
    }
}

function displayVideos(videos) {
    const grid = document.getElementById('videoGrid');
    if (videos.length === 0) {
        grid.innerHTML = '<p style="text-align:center;font-size:1.2rem;padding:50px;">📹 No videos uploaded yet. Be the first!</p>';
        return;
    }
    
    grid.innerHTML = videos.map(video => `
        <div class="video-card" onclick="playVideo(${video.id})">
            <img src="${API_URL}/videos/${video.id}/thumbnail" 
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

async function playVideo(videoId) {
    try {
        const response = await fetch(`${API_URL}/videos/${videoId}`);
        const data = await response.json();
        currentVideo = data;
        
        const player = document.getElementById('videoPlayer');
        player.style.display = 'flex';
        
        // Use the video stream endpoint
        const video = document.getElementById('mainVideo');
        video.src = `${API_URL}/videos/${videoId}/stream`;
        video.controls = true;
        video.load();
        
        document.getElementById('videoTitle').textContent = data.title;
        document.getElementById('videoDescription').textContent = data.description || 'No description';
        document.getElementById('likeCount').textContent = data.likes || 0;
        document.getElementById('dislikeCount').textContent = data.dislikes || 0;
        
        displayComments(data.comments || []);
        
        // Auto play
        video.play().catch(e => console.log('Auto-play prevented'));
    } catch (error) {
        alert('❌ Error loading video: ' + error.message);
    }
}

function closePlayer() {
    document.getElementById('videoPlayer').style.display = 'none';
    const video = document.getElementById('mainVideo');
    video.pause();
    video.src = '';
}

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
            alert('👍 Video liked!');
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to like');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

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
            alert('👎 Video disliked!');
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to dislike');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function shareVideo() {
    const url = window.location.origin + '/?v=' + currentVideo.id;
    if (navigator.share) {
        try {
            await navigator.share({
                title: currentVideo.title,
                text: 'Watch this amazing video on AKABAKUZE!',
                url: url
            });
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

function copyLink() {
    const url = window.location.origin + '/?v=' + currentVideo.id;
    navigator.clipboard.writeText(url).then(() => {
        alert('📋 Link copied to clipboard!');
        fetch(`${API_URL}/videos/${currentVideo.id}/share`, { method: 'POST' });
    }).catch(() => {
        prompt('Copy this link:', url);
    });
}

function downloadVideo() {
    const url = `${API_URL}/videos/${currentVideo.id}/stream`;
    const link = document.createElement('a');
    link.href = url;
    link.download = currentVideo.title + '.mp4';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

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
            // Reload comments
            const videoResponse = await fetch(`${API_URL}/videos/${currentVideo.id}`);
            const videoData = await videoResponse.json();
            displayComments(videoData.comments || []);
            alert('💬 Comment added!');
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to add comment');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

function displayComments(comments) {
    const list = document.getElementById('commentsList');
    if (!comments || comments.length === 0) {
        list.innerHTML = '<p style="color:#aaa;">No comments yet. Be the first!</p>';
        return;
    }
    list.innerHTML = comments.map(comment => `
        <div class="comment">
            <div class="comment-username">${comment.username}</div>
            <div>${comment.comment}</div>
            <small style="color:#888;">${new Date(comment.created_at).toLocaleString()}</small>
        </div>
    `).join('');
}

async function uploadVideo(e) {
    e.preventDefault();
    if (!currentUser || !['admin', 'super_admin'].includes(currentUser.role)) {
        alert('❌ Only admins can upload videos');
        return;
    }
    
    const formData = new FormData();
    formData.append('title', document.getElementById('videoTitleInput').value);
    formData.append('description', document.getElementById('videoDescriptionInput').value);
    const videoFile = document.getElementById('videoFile').files[0];
    const thumbnailFile = document.getElementById('thumbnailFile').files[0];
    
    if (!videoFile) {
        alert('Please select a video file');
        return;
    }
    
    formData.append('video', videoFile);
    if (thumbnailFile) {
        formData.append('thumbnail', thumbnailFile);
    }
    
    try {
        const response = await fetch(`${API_URL}/videos/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: formData
        });
        
        if (response.ok) {
            alert('✅ Video uploaded successfully to database!');
            document.getElementById('uploadForm').reset();
            showHome();
            loadVideos();
        } else {
            const data = await response.json();
            alert('❌ ' + (data.error || 'Upload failed'));
        }
    } catch (error) {
        alert('❌ Error: ' + error.message);
    }
}

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
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
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
            <h3>📋 Recent Activity</h3>
            ${logsHtml || 'No logs available'}
        `;
    } catch (error) {
        alert('Error loading admin data: ' + error.message);
    }
}

async function createAdmin(e) {
    e.preventDefault();
    if (!currentUser || currentUser.role !== 'super_admin') {
        alert('❌ Only super admin can create admins');
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
            alert('✅ Admin created successfully!');
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

function showHome() {
    document.getElementById('videoContainer').style.display = 'block';
    document.getElementById('uploadContainer').style.display = 'none';
    document.getElementById('adminContainer').style.display = 'none';
    document.getElementById('joinUsContainer').style.display = 'none';
    document.getElementById('videoPlayer').style.display = 'none';
    loadVideos();
}

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

function showJoinUs() {
    document.getElementById('videoContainer').style.display = 'none';
    document.getElementById('uploadContainer').style.display = 'none';
    document.getElementById('adminContainer').style.display = 'none';
    document.getElementById('joinUsContainer').style.display = 'block';
}

function requestProAccount() {
    if (!currentUser) {
        alert('Please login first');
        return;
    }
    alert('📧 Thank you for your interest! An admin will review your request and contact you soon.');
}

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

function showTrending() {
    showHome();
}

// Initialize
loadVideos();

// Check for video ID in URL
const urlParams = new URLSearchParams(window.location.search);
const videoId = urlParams.get('v');
if (videoId) {
    setTimeout(() => playVideo(videoId), 1000);
}

console.log('🚀 AKABAKUZE loaded successfully!');
