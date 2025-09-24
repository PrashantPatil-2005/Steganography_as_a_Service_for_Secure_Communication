import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('embed');
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [messageId, setMessageId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleEmbed = async (e) => {
    e.preventDefault();
    if (!file || !message || !passphrase) {
      setError('Please fill in all fields');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('message', message);
    formData.append('passphrase', passphrase);

    try {
      const response = await axios.post('/api/stego/embed', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleExtract = async (e) => {
    e.preventDefault();
    if (!file || !passphrase) {
      setError('Please select a file and enter passphrase');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('passphrase', passphrase);
    if (messageId) formData.append('message_id', messageId);

    try {
      const response = await axios.post('/api/stego/extract', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleAnalysis = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file for analysis');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post('/api/stego/analysis', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>🔒 Steganography as a Service</h1>
        <p>Hide and retrieve messages in images securely</p>
      </header>

      <div className="container">
        <div className="tabs">
          <button
            className={activeTab === 'embed' ? 'active' : ''}
            onClick={() => setActiveTab('embed')}
          >
            Hide Message
          </button>
          <button
            className={activeTab === 'extract' ? 'active' : ''}
            onClick={() => setActiveTab('extract')}
          >
            Reveal Message
          </button>
          <button
            className={activeTab === 'analysis' ? 'active' : ''}
            onClick={() => setActiveTab('analysis')}
          >
            Analyze Image
          </button>
        </div>

        {error && <div className="error">{error}</div>}

        {activeTab === 'embed' && (
          <form onSubmit={handleEmbed} className="form">
            <h2>Hide Message in Image</h2>
            <div className="form-group">
              <label>Select Image:</label>
              <input
                type="file"
                accept="image/*"
                onChange={(e) => setFile(e.target.files[0])}
                required
              />
            </div>
            <div className="form-group">
              <label>Secret Message:</label>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Enter your secret message here..."
                required
              />
            </div>
            <div className="form-group">
              <label>Passphrase:</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter encryption passphrase"
                required
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? 'Processing...' : 'Hide Message'}
            </button>
          </form>
        )}

        {activeTab === 'extract' && (
          <form onSubmit={handleExtract} className="form">
            <h2>Extract Message from Image</h2>
            <div className="form-group">
              <label>Select Stego Image:</label>
              <input
                type="file"
                accept="image/*"
                onChange={(e) => setFile(e.target.files[0])}
                required
              />
            </div>
            <div className="form-group">
              <label>Passphrase:</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter decryption passphrase"
                required
              />
            </div>
            <div className="form-group">
              <label>Message ID (optional):</label>
              <input
                type="text"
                value={messageId}
                onChange={(e) => setMessageId(e.target.value)}
                placeholder="For tamper detection and verification"
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? 'Processing...' : 'Extract Message'}
            </button>
          </form>
        )}

        {activeTab === 'analysis' && (
          <form onSubmit={handleAnalysis} className="form">
            <h2>Analyze Image for Steganography</h2>
            <div className="form-group">
              <label>Select Image:</label>
              <input
                type="file"
                accept="image/*"
                onChange={(e) => setFile(e.target.files[0])}
                required
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? 'Analyzing...' : 'Analyze Image'}
            </button>
          </form>
        )}

        {result && (
          <div className="result">
            {activeTab === 'embed' && result.message === 'Embedded successfully' && (
              <>
                <h3>Embed Successful</h3>
                <p><strong>Message ID:</strong> {result.message_id}</p>
                <p><strong>File Hash (SHA-256):</strong> {result.stego_hash}</p>
                <div style={{marginTop: '12px'}}>
                  <img
                    src={`/api/stego/preview/${result.message_id}`}
                    alt="stego preview"
                    style={{maxWidth: '100%', border: '1px solid #ddd', borderRadius: 6}}
                    onError={(e) => { e.currentTarget.style.display = 'none'; }}
                  />
                </div>
                <div style={{marginTop: '12px'}}>
                  <a
                    href={result.download_path}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="download-link"
                  >
                    Download Stego Image
                  </a>
                </div>
              </>
            )}

            {activeTab === 'extract' && result.data && (
              <>
                <h3>Extracted Message</h3>
                <textarea readOnly value={result.data} style={{width: '100%', minHeight: '120px'}} />
              </>
            )}

            {activeTab === 'analysis' && (result.chi_square_score !== undefined) && (
              <>
                <h3>Analysis Result</h3>
                <p><strong>Chi-square Score:</strong> {result.chi_square_score}</p>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
