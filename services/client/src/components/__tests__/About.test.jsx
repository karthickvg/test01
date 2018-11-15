import React from 'react';
import { shallow } from 'enzyme';
import renderer from 'react-test-renderer';

import About from '../About';

test('About renders a snapshot properly', () => {
	const tree = renderer.create(<About/>).toJSON();
	expect(tree).toMatchSnapshot();
});