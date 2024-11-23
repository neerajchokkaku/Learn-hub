import React, { useState } from 'react';
import './Test.css';

const questions = [
  {
    question: 'What is the capital of France?',
    options: ['London', 'Madrid', 'Paris', 'Berlin'],
    correctAnswer: 'Paris',
    marks: 1,
  },
  {
    question: 'Which planet is known as the Red Planet?',
    options: ['Venus', 'Mars', 'Jupiter', 'Saturn'],
    correctAnswer: 'Mars',
    marks: 1,
  },
  {
    question: 'What is the largest mammal?',
    options: ['Elephant', 'Blue Whale', 'Giraffe', 'Hippopotamus'],
    correctAnswer: 'Blue Whale',
    marks: 1,
  },
  {
    question: 'What is the chemical symbol for gold?',
    options: ['Au', 'Ag', 'Fe', 'Cu'],
    correctAnswer: 'Au',
    marks: 1,
  },
  {
    question: 'Which gas do plants absorb from the atmosphere?',
    options: ['Oxygen', 'Carbon Dioxide', 'Nitrogen', 'Hydrogen'],
    correctAnswer: 'Carbon Dioxide',
    marks: 1,
  },
];

const Test = () => {
  const [selectedOptions, setSelectedOptions] = useState(Array(questions.length).fill(''));
  const [showResult, setShowResult] = useState(false);
  const [totalMarks, setTotalMarks] = useState(0);

  const handleCheckAnswers = () => {
    let total = 0;
    selectedOptions.forEach((selectedOption, index) => {
      if (selectedOption === questions[index].correctAnswer) {
        total += questions[index].marks;
      }
    });
    setTotalMarks(total);
    setShowResult(true);
  };

  return (
    <div className="quiz-container">
      <h2>Quiz</h2>
      {questions.map((question, index) => (
        <div key={index} className="question-container">
          <p>{question.question}</p>
          <ul>
            {question.options.map((option, optionIndex) => (
              <li key={optionIndex}>
                <label>
                  <input
                    type="radio"
                    name={`question-${index}`}
                    value={option}
                    checked={selectedOptions[index] === option}
                    onChange={() => {
                      const newOptions = [...selectedOptions];
                      newOptions[index] = option;
                      setSelectedOptions(newOptions);
                    }}
                    disabled={showResult}
                  />
                  {option}
                </label>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <button onClick={handleCheckAnswers} disabled={showResult}>
        Submit
      </button>
      {showResult && (
        <div className="result-container">
          <p>Your Total Marks: {totalMarks} out of {questions.length}</p>
        </div>
      )}
    </div>
  );
};

export default Test;
