/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.as.cli.parsing.arguments;

import org.jboss.as.cli.CommandFormatException;
import org.jboss.as.cli.parsing.BackQuotesState;
import org.jboss.as.cli.parsing.CharacterHandler;
import org.jboss.as.cli.parsing.DefaultParsingState;
import org.jboss.as.cli.parsing.ParsingContext;
import org.jboss.as.cli.parsing.QuotesState;
import org.jboss.as.cli.parsing.WordCharacterHandler;

/**
 *
 * @author Alexey Loubyansky
 */
public class ArgumentValueState extends DefaultParsingState {

    public static final String ID = "ARG_VALUE";

    public static final ArgumentValueState INSTANCE = new ArgumentValueState();

    public static final String BYTES_TOKEN = "bytes{";
    private static final char[] BYTES_TOKEN_CHARS = BYTES_TOKEN.toCharArray();

    public ArgumentValueState() {
        super(ID);
        setEnterHandler(new CharacterHandler(){
            @Override
            public void handle(ParsingContext ctx) throws CommandFormatException {
                final char ch = ctx.getCharacter();
                switch(ch) {
                    case '"':
                        ctx.enterState(QuotesState.QUOTES_EXCLUDED);
                        break;
                    case '$':
                        ctx.enterState(ExpressionValueState.INSTANCE);
                        break;
                    case '`':
                        ctx.enterState(BackQuotesState.QUOTES_INCLUDED);
                        break;
                    default: {
                        if (ch == 'b') {
                            int tokenLength = getBytesToken(ctx);
                            if (tokenLength > 0) {
                                ctx.advanceLocation(tokenLength);
                                ctx.enterState(BytesValueState.INSTANCE);
                            } else {
                                ctx.getCallbackHandler().character(ctx);
                            }
                        } else {
                            ctx.getCallbackHandler().character(ctx);
                        }
                    }
                }
            }
        });
        setDefaultHandler(new CharacterHandler(){
            @Override
            public void handle(ParsingContext ctx) throws CommandFormatException {
                final char c = ctx.getCharacter();
                if((c == '}' || c == ']') && ctx.isLookingFor(c)) {
                    ctx.leaveState();
                } else {
                    if(c == '=' && !ctx.isDeactivated(c)) {
                        ctx.enterState(NameValueSeparatorState.INSTANCE);
                    } else {
                        WordCharacterHandler.IGNORE_LB_ESCAPE_ON.handle(ctx);
                    }
                }
            }});

        enterState(',', ListItemSeparatorState.INSTANCE);
        enterState('"', QuotesState.QUOTES_INCLUDED);
        enterState('`', BackQuotesState.QUOTES_INCLUDED);
        enterState('$', ExpressionValueState.INSTANCE);

        setReturnHandler(new CharacterHandler() {
            @Override
            public void handle(ParsingContext ctx) throws CommandFormatException {
                if(ctx.isEndOfContent()) {
                    return;
                }
                final char c = ctx.getCharacter();
                if(c == ',') {
                    ctx.leaveState();
                }
            }});
    }

    // handle white spaces.
    public static int getBytesToken(ParsingContext ctx) {
        String input = ctx.getInput().substring(ctx.getLocation());
        int tokenOffset = 0;
        int i = 0;
        char[] inputChars = input.toCharArray();
        for (; i < input.length(); i += 1) {
            char c = inputChars[i];
            if (c == ' ') {
                continue;
            }
            if (c != BYTES_TOKEN_CHARS[tokenOffset]) {
                return -1;
            } else {
                tokenOffset += 1;
                if (tokenOffset == BYTES_TOKEN_CHARS.length) {
                    // Found the token.
                    return i;
                }
            }
        }
        return -1;
    }
}
