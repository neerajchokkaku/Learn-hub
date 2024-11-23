import React, { useState } from "react";

const UPIPaymentForm = ({ isVisible }) => {
  const [upiId, setUpiId] = useState("");

  const handleUpiPayment = () => {
   
  };

  return (
    <div className={`mt-3 ${isVisible ? "d-block" : "d-none"}`}>
      <input
        type="text"
        className="form-control mb-2"
        placeholder="UPI ID"
        value={upiId}
        onChange={(e) => setUpiId(e.target.value)}
      />
      <button className="btn btn-primary" onClick={handleUpiPayment}>
        Pay with UPI
      </button>
    </div>
  );
};

const DebitCreditCardForm = ({ isVisible, cardType }) => {
  const [cardNumber, setCardNumber] = useState("");
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("");
  const [cvv, setCvv] = useState("");

  const handleDebitCreditCardPayment = () => {
    // Make a dummy debit/credit card payment here
  };

  return (
    <div className={`mt-3 ${isVisible ? "d-block" : "d-none"}`}>
      <input
        type="text"
        className="form-control mb-2"
        placeholder={`${cardType} Card Number`}
        value={cardNumber}
        onChange={(e) => setCardNumber(e.target.value)}
      />
      <input
        type="text"
        className="form-control mb-2"
        placeholder="Name"
        value={name}
        onChange={(e) => setName(e.target.value)}
      />
      <input
        type="text"
        className="form-control mb-2"
        placeholder="Expiry (MM/YYYY)"
        value={expiry}
        onChange={(e) => setExpiry(e.target.value)}
      />
      <input
        type="text"
        className="form-control mb-2"
        placeholder="CVV"
        value={cvv}
        onChange={(e) => setCvv(e.target.value)}
      />
      <button className="btn btn-primary" onClick={handleDebitCreditCardPayment}>
        Pay with {cardType} Card
      </button>
    </div>
  );
};

const PaymentPage = () => {
  const [isUPIFormVisible, setIsUPIFormVisible] = useState(false);
  const [isDebitCardFormVisible, setIsDebitCardFormVisible] = useState(false);
  const [isCreditCardFormVisible, setIsCreditCardFormVisible] = useState(false);

  const toggleFormVisibility = (formType) => {
    setIsUPIFormVisible(formType === "upi");
    setIsDebitCardFormVisible(formType === "debit");
    setIsCreditCardFormVisible(formType === "credit");
  };

  return (
    <div className="container mt-5">
      <h1>Select Payment Method</h1>
      <div className="row">
        <div className="col-lg-4 mb-4">
          <div className="card">
            <div className="card-body">
              <img src="https://www.shutterstock.com/image-vector/bangalore-india-22-august-2023-260nw-2350683383.jpg" alt="UPI Logo" width="100" />
              <h2 className="card-title">UPI</h2>
              <button className="btn btn-primary" onClick={() => toggleFormVisibility("upi")}>
                Pay with UPI
              </button>
              <UPIPaymentForm isVisible={isUPIFormVisible} />
            </div>
          </div>
        </div>
        <div className="col-lg-4 mb-4">
          <div className="card">
            <div className="card-body">
              <img src="https://todaymoneytalk.files.wordpress.com/2013/01/2e1d0-matercard.jpeg" alt="Debit Card Logo" width="100" />
              <h2 className="card-title">Debit Card</h2>
              <button className="btn btn-primary" onClick={() => toggleFormVisibility("debit")}>
                Pay with Debit Card
              </button>
              <DebitCreditCardForm isVisible={isDebitCardFormVisible} cardType="Debit" />
            </div>
          </div>
        </div>
        <div className="col-lg-4 mb-4">
          <div className="card">
            <div className="card-body">
              <img src="https://t4.ftcdn.net/jpg/04/06/75/39/360_F_406753914_SFSBhjhp6kbHblNiUFZ1MXHcuEKe7e7P.jpg" alt="Credit Card Logo" width="100" />
              <h2 className="card-title">Credit Card</h2>
              <button className="btn btn-primary" onClick={() => toggleFormVisibility("credit")}>
                Pay with Credit Card
              </button>
              <DebitCreditCardForm isVisible={isCreditCardFormVisible} cardType="Credit" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PaymentPage;
