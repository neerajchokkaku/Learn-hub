import React from "react";
import 'bootstrap/dist/css/bootstrap.min.css';

export default function Home() {
    return (
        <div className="d-flex flex-column align-items-center justify-content-center bg-primary" style={{ height: '100vh' }}>
            <h1 className="text-light mb-4">Welcome to the Video Section</h1> {/* Added header */}
            <div className="ratio ratio-16x9" style={{ maxWidth: '900px', backgroundColor: 'rgba(255,255,255,0.9)', padding: '20px', borderRadius: '15px' }}>
                <iframe
                    src="https://www.youtube.com/embed/xNRJwmlRBNU?si=2ScEy3d9VFC4N_4c"
                    title="YouTube video"
                    allowFullScreen
                    style={{ width: '100%', height: '100%', borderRadius: '10px' }}
                ></iframe>
            </div>
        </div>
    );
}