"""
VSec — Message Conversion Utilities

Helper functions for converting between LangChain message objects
and simple dict format used by the API and bot.
"""
from typing import Optional


def extract_message_content(message) -> Optional[str]:
    """
    Extract text content from a LangChain message object.
    
    Handles different content types:
    - str: simple text response
    - list[ContentBlock]: complex response with tool calls, etc.
    - None: empty message
    
    Args:
        message: LangChain message object (HumanMessage, AIMessage, etc.)
    
    Returns:
        Extracted text content or None if no text found
    """
    content = getattr(message, 'content', None)
    
    if content is None:
        return None
    
    # Simple string content
    if isinstance(content, str):
        return content
    
    # List content (ContentBlock format from Anthropic)
    if isinstance(content, list):
        text_parts = []
        for block in content:
            if isinstance(block, dict):
                block_type = block.get("type", "")
                
                # Text block
                if block_type == "text":
                    text = block.get("text", "")
                    if text:
                        text_parts.append(text)
                
                # Tool use block - record the tool call
                elif block_type == "tool_use":
                    tool_name = block.get("name", "unknown_tool")
                    text_parts.append(f"[Using tool: {tool_name}]")
                
                # Tool result block
                elif block_type == "tool_result":
                    result_content = block.get("content", [])
                    if isinstance(result_content, list):
                        for item in result_content:
                            if isinstance(item, dict) and item.get("type") == "text":
                                text_parts.append(item.get("text", ""))
                    elif isinstance(result_content, str):
                        text_parts.append(result_content)
                
                # Image block - skip
                elif block_type == "image":
                    text_parts.append("[Image content]")
            
            # Handle string blocks
            elif isinstance(block, str):
                text_parts.append(block)
        
        return "\n".join(text_parts) if text_parts else None
    
    # Fallback
    return str(content) if content else None


def convert_langchain_messages(messages: list) -> list[dict]:
    """
    Convert a list of LangChain message objects to simple dict format.
    
    Args:
        messages: List of LangChain message objects
    
    Returns:
        List of {"role": str, "content": str} dicts
    
    Example:
        >>> from langchain_core.messages import HumanMessage, AIMessage
        >>> msgs = [HumanMessage(content="hello"), AIMessage(content="hi there")]
        >>> convert_langchain_messages(msgs)
        [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi there"}]
    """
    result = []
    
    for msg in messages:
        msg_type = getattr(msg, 'type', None)
        
        # Map message types to roles
        if msg_type == "human":
            role = "user"
        elif msg_type == "ai":
            role = "assistant"
        elif msg_type == "tool":
            role = "tool"
        elif msg_type == "system":
            role = "system"
        else:
            continue  # Skip unknown types
        
        # Extract content
        content = extract_message_content(msg)
        if content:
            result.append({"role": role, "content": content})
    
    return result


def get_last_ai_response(messages: list) -> str:
    """
    Extract the last AI response from a list of LangChain messages.
    
    Args:
        messages: List of LangChain message objects
    
    Returns:
        The content of the last AI message, or empty string if none found
    """
    for msg in reversed(messages):
        msg_type = getattr(msg, 'type', None)
        if msg_type == "ai":
            content = extract_message_content(msg)
            if content:
                return content
    
    return ""


def build_langchain_messages(message_dicts: list[dict]) -> list:
    """
    Convert simple message dicts back to LangChain message objects.
    
    Args:
        message_dicts: List of {"role": "user"|"assistant", "content": str}
    
    Returns:
        List of LangChain message objects
    """
    from langchain_core.messages import HumanMessage, AIMessage
    
    result = []
    for msg in message_dicts:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        
        if role == "user":
            result.append(HumanMessage(content=content))
        else:
            result.append(AIMessage(content=content))
    
    return result
