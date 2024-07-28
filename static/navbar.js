window.onload = () => {
    addNavbarToDOM();
}

const addNavbarToDOM = () => {
    const navbar = document.querySelector('.navbar');
    if (!navbar) { return; }
    let link = document.createElement('link');
    link.type = 'text/css';
    link.rel = 'stylesheet';
    link.href = '../static/navbar.css';
    document.head.appendChild(link);
    navbar.innerHTML = navbarTemplate();
}

const navbarTemplate = () => {
    return '<span class="montserrat-font nav-logo">VULNX</span><div class=nav-links><a class="ibm-plex-serif-regular nav-link"href=../ >Home</a> <a class="ibm-plex-serif-regular nav-link"href=../about/ >About</a> <a class="ibm-plex-serif-regular nav-link"href=../projects/ >Projects</a></div>';
}