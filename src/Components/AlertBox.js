import React from 'react';

const AlertBox = ({ message, type }) => {
  const alertStyle = {
    padding: '15px',
    marginBottom: '20px',
    border: '1px solid transparent',
    borderRadius: '5px',
    fontSize: '16px',
    textAlign: 'center',
  };

  // Set different styles based on the alert type
  if (type === 'success') {
    alertStyle.backgroundColor = '#d4edda';
    alertStyle.borderColor = '#c3e6cb';
    alertStyle.color = '#155724';
  } else if (type === 'error') {
    alertStyle.backgroundColor = '#f8d7da';
    alertStyle.borderColor = '#f5c6cb';
    alertStyle.color = '#721c24';
  }

  return <div style={alertStyle}>{message}</div>;
};

export default AlertBox;
