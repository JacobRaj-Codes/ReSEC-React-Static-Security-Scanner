import React, { useState, useEffect } from "react";

function BlogApp() {
  const [content, setContent] = useState("");

  // ❌ 1. Using dangerouslySetInnerHTML (XSS risk)
  const createMarkup = () => {
    return { __html: content };
  };

  // ❌ 2. Fetching from insecure HTTP endpoint
  useEffect(() => {
    fetch("http://example.com/api/posts")
      .then((res) => res.json())
      .then((data) => setContent(data.html));
  }, []);

  // ❌ 3. Hardcoded API key
  const API_KEY = "api_key_12345ABCDEF";

  // ❌ 4. Using eval()
  function runUserCode(input) {
    return eval(input);
  }

  // ❌ 5. Storing token in localStorage
  const handleLogin = (token) => {
    localStorage.setItem("userToken", token);
  };

  return (
    <div>
      <h1>My Blog App</h1>
      <div dangerouslySetInnerHTML={createMarkup()} />
      <button onClick={() => handleLogin("test123")}>Login</button>
    </div>
  );
}

export default BlogApp;
