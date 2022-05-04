import React from 'react';
import { BrowserRouter as Router, Routes, Route }
    from 'react-router-dom';
import Main from './Main';
import About from './About';

function App() {
    return (
        <Router>
            <Routes>
                <Route exact path='/' element={<Main />} />
                <Route path='/about' element={<About />} />
            </Routes>
        </Router>
    );
}

export default App;
