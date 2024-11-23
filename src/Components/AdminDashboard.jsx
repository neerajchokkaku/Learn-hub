import React from "react";
import { Link } from "react-router-dom";
import { FaPlus, FaList, FaCog, FaUsers, FaSignOutAlt } from "react-icons/fa";
import { useNavigate } from 'react-router-dom';
function AdminDashboard() {

    const navigate = useNavigate();

    const handleLogout = () => {
        navigate('/admin');
    }

    return (
        <>
            <nav className="navbar navbar-expand-lg navbar-light bg-warning">
                <div className="container">
                    <Link className="navbar-brand" to="/">
                        CRUD Operations
                    </Link>
                    <button
                        className="navbar-toggler"
                        type="button"
                        data-bs-toggle="collapse"
                        data-bs-target="#navbarNav"
                        aria-controls="navbarNav"
                        aria-expanded="false"
                        aria-label="Toggle navigation"
                    >
                        <span className="navbar-toggler-icon"></span>
                    </button>
                    <div className="collapse navbar-collapse justify-content-end" id="navbarNav">
                        <ul className="navbar-nav">
                            <li className="nav-item">
                                <Link className="nav-link" to="/add-course">
                                    <FaPlus className="me-1" /> Add Course
                                </Link>
                            </li>
                            <li className="nav-item">
                                <Link className="nav-link" to="/course-list">
                                    <FaList className="me-1" /> Course List
                                </Link>
                            </li>

                            <li className="nav-item">
                                <Link className="nav-link" to="/user-problems">
                                    <FaList className="me-1" /> User problems
                                </Link>
                            </li>

                            <li className="nav-item">
                                <button className="nav-link" onClick={handleLogout}>
                                    <FaSignOutAlt className="me-1" /> Logout
                                </button>
                            </li>
                        </ul>
                    </div>
                </div>
            </nav>
            <h1 style={{ textAlign: 'center' }} className="mt-5">Admin Privelgies</h1>
            <div className="container mt-5 d-flex justify-content-center align-items-center">
                <div className="row">
                    <div className="col-md-6 mb-4">

                        <div className="card text-center">
                            <div className="card-body">
                                <FaCog className="card-icon mb-3" />
                                <h5 className="card-title">Manage Courses</h5>
                                <p className="card-text">Add, edit, and delete courses. Manage course settings.</p>

                            </div>
                        </div>
                    </div>
                    <div className="col-md-6 mb-4">
                        <div className="card text-center">
                            <div className="card-body">
                                <FaUsers className="card-icon mb-3" />
                                <h5 className="card-title">Manage Users</h5>
                                <p className="card-text">Add, edit, and delete users. Manage user permissions.</p>

                            </div>
                        </div>
                    </div>
                    <div className="col-md-6 mb-4">
                        <div className="card text-center">
                            <div className="card-body">
                                <FaCog className="card-icon mb-3" />
                                <h5 className="card-title">Manage Settings</h5>
                                <p className="card-text">Configure application settings and preferences.</p>

                            </div>
                        </div>
                    </div>
                    <div className="col-md-6 mb-4">
                        <div className="card text-center">
                            <div className="card-body">
                                <FaList className="card-icon mb-3" />
                                <h5 className="card-title">Generate Reports</h5>
                                <p className="card-text">View and export detailed reports and analytics.</p>

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}

export default AdminDashboard;
