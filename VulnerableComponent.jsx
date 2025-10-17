import React, { useState, useRef, useEffect } from 'react';

/**
 * Sample Vulnerable Component for Testing
 * This file contains intentional security vulnerabilities for demonstration
 */

const VulnerableComponent = ({ userInput, userData }) => {
  const [htmlContent, setHtmlContent] = useState('');
  const [comment, setComment] = useState('');
  const contentRef = useRef(null);

  // VULNERABILITY 1: Dangerous innerHTML without sanitization
  const renderUnsafeHTML = () => {
    return (
      <div dangerouslySetInnerHTML={{ __html: userInput }} />
    );
  };

  // VULNERABILITY 2: Using eval with user input
  const executeUserCode = (code) => {
    try {
      eval(code);  // CRITICAL: Never use eval with user input
    } catch (error) {
      console.log('Error executing code');
    }
  };

  // VULNERABILITY 3: document.write usage
  const writeToDocument = (content) => {
    document.write(content);  // Vulnerable to XSS
  };

  // VULNERABILITY 4: Target blank without noopener
  const ExternalLink = () => {
    return (
      <a href="https://external-site.com" target="_blank">
        Click here
      </a>
    );
  };

  // VULNERABILITY 5: Unsafe ref manipulation
  useEffect(() => {
    if (contentRef.current) {
      contentRef.current.innerHTML = userData.comment;  // XSS risk
    }
  }, [userData]);

  // VULNERABILITY 6: localStorage without sanitization
  const renderStoredData = () => {
    const storedData = localStorage.getItem('userData');
    return <div>{storedData}</div>;  // XSS if not sanitized
  };

  // VULNERABILITY 7: Unsafe iframe
  const EmbedContent = ({ url }) => {
    return <iframe src={url} />;  // Missing sandbox attribute
  };

  // VULNERABILITY 8: Prototype pollution vulnerability
  const mergeObjects = (target, source) => {
    for (let key in source) {
      target[key] = source[key];  // Can pollute __proto__
    }
  };

  // VULNERABILITY 9: Hardcoded API key
  const API_KEY = 'AIzaSyD1234567890abcdefghijklmnopqrstuvw';  // Never hardcode
  
  // VULNERABILITY 10: Client-side authentication
  const isAuthenticated = () => {
    return localStorage.getItem('authToken') !== null;  // Insecure
  };

  // VULNERABILITY 11: window.open without protection
  const openExternalWindow = (url) => {
    window.open(url, '_blank');  // Tabnabbing vulnerability
  };

  // VULNERABILITY 12: Unvalidated props in href
  const DynamicLink = () => {
    return <a href={userInput}>Click</a>;  // XSS via javascript: protocol
  };

  // VULNERABILITY 13: Console.log with sensitive data
  const logUserData = () => {
    console.log('User data:', userData.password, userData.creditCard);
  };

  // VULNERABILITY 14: Error message exposure
  const handleError = (error) => {
    return <div>Error: {error.stack}</div>;  // Exposes stack trace
  };

  // VULNERABILITY 15: setTimeout with string
  const delayedExecution = (code) => {
    setTimeout(code, 1000);  // Code injection risk
  };

  return (
    <div ref={contentRef}>
      <h1>Vulnerable Component Demo</h1>
      
      {renderUnsafeHTML()}
      
      <ExternalLink />
      
      <EmbedContent url={userInput} />
      
      <DynamicLink />
      
      <button onClick={() => executeUserCode(userInput)}>
        Execute Code
      </button>
      
      <button onClick={() => openExternalWindow(userInput)}>
        Open External
      </button>
      
      <div>
        {renderStoredData()}
      </div>
      
      <style jsx>{`
        div {
          ${userInput}  /* CSS injection */
        }
      `}</style>
    </div>
  );
};

export default VulnerableComponent;
