/*
 * keyboardInteractive.hpp
 *
 *  Created on: 21 juin 2009
 *      Author: aris
 */

#ifndef KEYBOARDINTERACTIVE_HPP_
#define KEYBOARDINTERACTIVE_HPP_
#include "session.hpp"
namespace ssh {

class KeyboardInteractive {
public:
	KeyboardInteractive();
	~KeyboardInteractive();
	int getPromptCount();
	std::string getName();
	std::string getInstruction();
	std::string getPrompt(int prompt, bool &mustecho);
	void setAnswer(int prompt, std::string answer);
};

}

#endif /* KEYBOARDINTERACTIVE_HPP_ */
