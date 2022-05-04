import React from 'react';
import { BrowserRouter as Router, Routes, Route }
    from 'react-router-dom';
import Main from './Main';
import DBDisplay from './DBDisplay';

function App() {
    return (
        <Router>
            <Routes>
                <Route exact path='/' element={<Main />} />
                <Route path='/db-display' element={<DBDisplay />} />
            </Routes>
        </Router>
    );
}

export default App;
