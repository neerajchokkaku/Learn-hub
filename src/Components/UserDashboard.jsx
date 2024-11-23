import React, { useState } from 'react';
import Sidebar from './Sidebar.js';
import { SidebarData } from './SidebarData';
import { FaSearch } from 'react-icons/fa';
import { Link } from 'react-router-dom';

import { faFacebook, faInstagram } from '@fortawesome/free-brands-svg-icons'

import { faEnvelope } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'


const cardData = [
  {
    title: "Soft Skills",
    description: "Soft skills encompass interpersonal skills, communication abilities, adaptability, problem-solving, teamwork, and emotional intelligence.",
    image: "images/2.jpg",
    rating: 4,
  },
  {
    title: "Data Science and Analytics",
    description: "Data science and analytics involve extracting insights from data through statistical analysis, machine learning, and data visualization to inform data-driven decision-making.",
    image: "images/seo.png",
    rating: 3, // Add a rating for the course
  },
  {
    title: "E-Commerce",
    description: "An online marketplace enabling the buying and selling of goods and services over the internet.",
    image: "images/6.jpg",
    rating: 2, // Add a rating for the course
  },

  {
    title: "Sales and Marketing",
    description: "Sales and marketing involve promoting and selling products or services through strategic communication, market research, advertising, and relationship-building to drive business growth.",
    image: "images/ui-ux.png",
    rating: 4, // Add a rating for the course
  },
  {
    title: "Cybersecurity",
    description: "Cybersecurity is the practice of protecting systems, networks, and data from digital threats and attacks to ensure confidentiality, integrity, and availability.",
    image: "images/3.jpg",
    rating: 2, // Add a rating for the course
  },
  {
    title: "Financial Management",
    description: "Financial Management involves optimizing the allocation of resources to maximize financial efficiency and achieve business goals.",
    image: "images/4.jpg",
    rating: 5, // Add a rating for the course
  },

  {
    title: "Graphic Design",
    description: "Graphic design is the art of visually communicating ideas and messages through creative use of imagery, typography, and layout to engage and inform audiences.",
    image: "images/5.jpg",
    rating: 5, // Add a rating for the course
  },

  // Add more card data as needed
];

const Dashboard = () => {
  const [searchTerm, setSearchTerm] = useState('');

  const cardStyle = {
    display: 'flex',
    flexWrap: 'wrap',
    justifyContent: 'center',
  };

  const cardItemStyle = {
    margin: '10px',
    padding: '10px',
    width: '300px',
  };

  return (
    <div className="dashboard-container">
      <Sidebar sidebarData={SidebarData} />
      <div className="container mt-5">
        <div className="d-flex justify-content-center search-bar">
          <input
            type="text"
            placeholder="Search ....."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="form-control search-input"
          />
          <div className="input-group-append">
            <span className="input-group-text search-icon">
              <FaSearch className="search-icon" style={{ fontSize: "20px" }} />
            </span>
          </div>
        </div><br></br>

        <div style={cardStyle}>
          {cardData
            .filter((card) =>
              card.title.toLowerCase().includes(searchTerm.toLowerCase())
            )
            .map((card, index) => (
              <div key={index} className="card" style={cardItemStyle}>
                <Link to="/view-courses">
                  <div className="card-content">
                    <img src={card.image} alt={card.title} className="card-image" /><br></br>

                  </div>
                </Link><br></br>
                <h4 className="card-title">{card.title}</h4>
                <p className="card-description">{card.description}</p>
                <div className="star-rating">
                  {getStarRating(card.rating)}
                </div>
              </div>

            ))}
        </div>
      </div>
      <footer>
        <div class="container">
          <div class="row">
            <div class="col" id="company">
              <img src="images/logo.png" alt="" class="logo" />
              <p>
                "Our mission at Learn Hub is to provide accessible, high-quality, and diverse educational content to learners of all backgrounds."

              </p>
              <div class="social">
                <a href="#"><i class="fab fa-facebook"></i></a>
                <a href="#"><i class="fab fa-instagram"></i></a>
                <a href="#"><i class="fab fa-youtube"></i></a>
                <a href="#"><i class="fab fa-twitter"></i></a>
                <a href="#"><i class="fab fa-linkedin"></i></a>
              </div>
            </div>


            <div class="col" id="services">
              <h3>Services</h3>
              <div class="links">
                <a href="#">E-learning</a>
                <a href="#">Communication and support</a>
                <a href="#">Assesments</a>
                <a href="#">Course content</a>
              </div>
            </div>

            <div class="col" id="useful-links">
              <h3>Links</h3>
              <div class="links">
                <a href="#">About</a>
                <a href="#">Services</a>
                <a href="#">Our Policy</a>
                <a href="#">Help</a>
              </div>
            </div>

            <div class="col" id="contact">
              <h3>Contact</h3>
              <div class="contact-details">
                <i class="fa fa-location"></i>
                <p>FF-42,Hyderabad, <br /> Telangana, INDIA</p>
              </div>
              <div class="contact-details">
                <i class="fa fa-phone"></i>
                <p>+1-8755856858</p>
              </div>
            </div>
          </div><br></br>

          <p className="card-text text-black">
            Follow us on :

            <div className='justify-content-evenly'>
              <a href="https://facebook.com">
                <FontAwesomeIcon icon={faFacebook} style={{ color: 'black' }} />
              </a>&nbsp; &nbsp;
              <a href="https://instagram.com">
                <FontAwesomeIcon icon={faInstagram} style={{ color: 'black' }} />
              </a>&nbsp;  &nbsp;
              <a href="mailto:youremail@example.com">
                <FontAwesomeIcon icon={faEnvelope} style={{ color: 'black' }} />
              </a>
            </div>
          </p>

        </div>
      </footer>

    </div>
  );
};
const getStarRating = (rating) => {
  const starStyle = {
    color: '#4CAF50', // Green color for filled stars
  };

  const emptyStarStyle = {
    color: '#fff', // White color for empty stars
  };

  const filledStars = (
    <span style={starStyle}>
      {'★'.repeat(Math.floor(rating))} {/* Filled stars */}
    </span>
  );

  const halfStar = rating % 1 !== 0 ? <span style={starStyle}>★</span> : null; // Half star for non-integer ratings

  const emptyStars = (
    <span style={emptyStarStyle}>
      {'☆'.repeat(5 - Math.ceil(rating))} {/* Empty stars */}
    </span>
  );

  return (
    <span>
      {filledStars}
      {halfStar}
      {emptyStars}
    </span>
  );
};



export default Dashboard;
